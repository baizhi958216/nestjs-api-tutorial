import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}
  async signin(dto: AuthDto) {
    // 通过邮箱查找用户
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    // 不存在则抛出异常
    if (!user) throw new ForbiddenException('邮箱不存在');
    // 对比密码
    const pwMatches = await argon.verify(user.hash, dto.password);
    // 密码错误抛出异常
    if (!pwMatches) throw new ForbiddenException('密码错误');
    delete user.hash;
    // 返回jwt
    return this.signToken(user.id, user.email);
  }

  async signup(dto: AuthDto) {
    // hash加密密码
    const hash = await argon.hash(dto.password);
    try {
      // 往数据库新增user
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
        /* // 选择需要返回在user的内容
      select: {
        id: true,
        email: true,
        createAt: true,
      }, */
      });
      // 移除hash
      // delete user.hash;
      // 返回jwt
      return this.signToken(user.id, user.email);
    } catch (error) {
      if (error.code === 'P2002') {
        throw new ForbiddenException('邮箱已存在');
      }
      throw error;
    }
  }

  // jwt签名
  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };
    // 签名
    const secret = this.config.get('JWT_SECRET');
    // 生成token
    const token = await this.jwt.signAsync(payload, {
      secret: secret,
      expiresIn: '15m',
    });

    return {
      access_token: token,
    };
  }
}
