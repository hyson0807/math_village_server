import {
  ConflictException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { OAuth2Client } from 'google-auth-library';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import {
  USER_PUBLIC_SELECT,
  USER_WITH_PASSWORD_SELECT,
  USER_WITH_REFRESH_SELECT,
} from '../common/constants/user-select';

interface GoogleUserInfo {
  sub: string;
  email: string;
  name?: string;
  picture?: string;
}

interface AppleUserInfo {
  sub: string;
  email?: string;
}

// refresh token 잔여 수명이 이 값 미만일 때만 새 refresh token 으로 회전한다.
// 매 refresh 마다 회전하면 응답 유실(타임아웃/앱 종료) 시 클라이언트는 옛 토큰,
// DB 는 새 해시가 되어 다음 refresh 가 401 로 끊기는 race 가 있다.
const REFRESH_ROTATE_THRESHOLD_MS = 3 * 24 * 60 * 60 * 1000; // 3일

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly accessSecret: string;
  private readonly refreshSecret: string;
  private readonly googleClient: OAuth2Client;
  private readonly appleJWKS: ReturnType<typeof createRemoteJWKSet>;
  private readonly appleBundleId: string;

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {
    this.accessSecret = config.getOrThrow<string>('JWT_ACCESS_SECRET');
    this.refreshSecret = config.getOrThrow<string>('JWT_REFRESH_SECRET');
    this.googleClient = new OAuth2Client(
      config.get<string>('GOOGLE_CLIENT_ID'),
    );
    this.appleJWKS = createRemoteJWKSet(
      new URL('https://appleid.apple.com/auth/keys'),
    );
    this.appleBundleId = config.get<string>('APPLE_BUNDLE_ID') ?? '';
  }

  async googleSignIn(idToken?: string, accessToken?: string) {
    let info: GoogleUserInfo | null = null;

    if (idToken) {
      try {
        info = await this.verifyGoogleIdToken(idToken);
      } catch (e) {
        this.logger.warn(`Google idToken 검증 실패, accessToken 폴백: ${e}`);
      }
    }
    if (!info && accessToken) {
      info = await this.fetchGoogleUserInfo(accessToken);
    }
    if (!info) {
      throw new UnauthorizedException('Google 인증에 실패했습니다.');
    }

    // 1) googleId로 먼저 찾기
    let user = await this.prisma.user.findUnique({
      where: { googleId: info.sub },
      select: USER_PUBLIC_SELECT,
    });

    // 2) 없으면 email로 찾아서 googleId 연결 (기존 이메일/비밀번호 가입자 지원)
    if (!user) {
      const existing = await this.prisma.user.findUnique({
        where: { email: info.email },
        select: { id: true },
      });
      if (existing) {
        user = await this.prisma.user.update({
          where: { id: existing.id },
          data: { googleId: info.sub },
          select: USER_PUBLIC_SELECT,
        });
      }
    }

    // 3) 그래도 없으면 신규 생성
    if (!user) {
      user = await this.prisma.user.create({
        data: {
          googleId: info.sub,
          email: info.email,
          name: info.name ?? null,
        },
        select: USER_PUBLIC_SELECT,
      });
    }

    const tokens = await this.issueTokens(user.id);
    return { ...tokens, user };
  }

  async appleSignIn(dto: {
    identityToken: string;
    fullName?: string;
    email?: string;
  }) {
    const apple = await this.verifyAppleToken(dto.identityToken);
    const resolvedEmail = apple.email ?? dto.email;

    let user = await this.prisma.user.findUnique({
      where: { appleId: apple.sub },
      select: USER_PUBLIC_SELECT,
    });

    if (!user && resolvedEmail) {
      const existing = await this.prisma.user.findUnique({
        where: { email: resolvedEmail },
        select: { id: true },
      });
      if (existing) {
        user = await this.prisma.user.update({
          where: { id: existing.id },
          data: { appleId: apple.sub },
          select: USER_PUBLIC_SELECT,
        });
      }
    }

    if (!user) {
      if (!resolvedEmail) {
        throw new UnauthorizedException(
          '최초 Apple 로그인에는 이메일이 필요합니다.',
        );
      }
      user = await this.prisma.user.create({
        data: {
          appleId: apple.sub,
          email: resolvedEmail,
          name: dto.fullName ?? null,
        },
        select: USER_PUBLIC_SELECT,
      });
    }

    const tokens = await this.issueTokens(user.id);
    return { ...tokens, user };
  }

  private async verifyGoogleIdToken(idToken: string): Promise<GoogleUserInfo> {
    try {
      const audiences = [
        this.config.get<string>('GOOGLE_CLIENT_ID'),
        this.config.get<string>('GOOGLE_IOS_CLIENT_ID'),
        this.config.get<string>('GOOGLE_ANDROID_CLIENT_ID'),
      ].filter(Boolean) as string[];

      const ticket = await this.googleClient.verifyIdToken({
        idToken,
        audience: audiences,
      });
      const payload = ticket.getPayload();
      if (!payload?.sub || !payload?.email) {
        throw new Error('Missing user info');
      }
      return {
        sub: payload.sub,
        email: payload.email,
        name: payload.name,
        picture: payload.picture,
      };
    } catch {
      throw new UnauthorizedException('유효하지 않은 Google ID 토큰입니다.');
    }
  }

  private async fetchGoogleUserInfo(
    accessToken: string,
  ): Promise<GoogleUserInfo> {
    try {
      const res = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (!res.ok) throw new Error('Failed to fetch user info');
      const data = (await res.json()) as Record<string, unknown>;
      if (!data.sub || !data.email) throw new Error('Missing user info');
      return {
        sub: data.sub as string,
        email: data.email as string,
        name: data.name as string | undefined,
        picture: data.picture as string | undefined,
      };
    } catch {
      throw new UnauthorizedException(
        '유효하지 않은 Google access 토큰입니다.',
      );
    }
  }

  private async verifyAppleToken(
    identityToken: string,
  ): Promise<AppleUserInfo> {
    try {
      const { payload } = await jwtVerify(identityToken, this.appleJWKS, {
        issuer: 'https://appleid.apple.com',
        audience: this.appleBundleId,
      });
      if (!payload.sub) throw new Error('Missing sub claim');
      return {
        sub: payload.sub,
        email: payload.email as string | undefined,
      };
    } catch {
      throw new UnauthorizedException('유효하지 않은 Apple 토큰입니다.');
    }
  }

  async register(dto: RegisterDto) {
    const passwordHash = await bcrypt.hash(dto.password, 10);

    const user = await this.prisma.user
      .create({
        data: {
          email: dto.email,
          passwordHash,
        },
        select: USER_PUBLIC_SELECT,
      })
      .catch((e: unknown) => {
        if (
          typeof e === 'object' &&
          e !== null &&
          'code' in e &&
          (e as { code: unknown }).code === 'P2002'
        ) {
          throw new ConflictException('이미 사용 중인 이메일입니다.');
        }
        throw e;
      });

    const tokens = await this.issueTokens(user.id);
    return { ...tokens, user };
  }

  async login(dto: LoginDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
      select: USER_WITH_PASSWORD_SELECT,
    });
    if (!user || !user.passwordHash) {
      throw new UnauthorizedException(
        '이메일 또는 비밀번호가 올바르지 않습니다.',
      );
    }

    const valid = await bcrypt.compare(dto.password, user.passwordHash);
    if (!valid) {
      throw new UnauthorizedException(
        '이메일 또는 비밀번호가 올바르지 않습니다.',
      );
    }

    const { passwordHash: _, ...publicUser } = user;
    const tokens = await this.issueTokens(publicUser.id);
    return { ...tokens, user: publicUser };
  }

  async refresh(refreshToken: string) {
    let payload: { sub: string; exp: number };
    try {
      payload = await this.jwt.verifyAsync(refreshToken, {
        secret: this.refreshSecret,
      });
    } catch {
      throw new UnauthorizedException('유효하지 않은 토큰입니다.');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      select: USER_WITH_REFRESH_SELECT,
    });
    if (!user || !user.refreshToken) {
      throw new UnauthorizedException('유효하지 않은 토큰입니다.');
    }

    const valid = await bcrypt.compare(refreshToken, user.refreshToken);
    if (!valid) {
      throw new UnauthorizedException('유효하지 않은 토큰입니다.');
    }

    const { refreshToken: _rt, ...publicUser } = user;

    // 만료 임박 시에만 회전 — 평소에는 기존 refresh token 을 그대로 돌려줘
    // 응답 유실 시에도 클라이언트가 들고 있는 토큰이 계속 유효하도록 한다.
    const msLeft = payload.exp * 1000 - Date.now();
    if (msLeft < REFRESH_ROTATE_THRESHOLD_MS) {
      const tokens = await this.issueTokens(publicUser.id);
      return { ...tokens, user: publicUser };
    }

    const accessToken = await this.jwt.signAsync(
      { sub: publicUser.id },
      { secret: this.accessSecret, expiresIn: '15m' },
    );
    return { accessToken, refreshToken, user: publicUser };
  }

  async logout(userId: string) {
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: null },
    });
  }

  private async issueTokens(userId: string) {
    const payload = { sub: userId };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwt.signAsync(payload, {
        secret: this.accessSecret,
        expiresIn: '15m',
      }),
      this.jwt.signAsync(payload, {
        secret: this.refreshSecret,
        expiresIn: '7d',
      }),
    ]);

    const hashedRefresh = await bcrypt.hash(refreshToken, 10);
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: hashedRefresh },
    });

    return { accessToken, refreshToken };
  }
}
