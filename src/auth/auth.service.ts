import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
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
    // 返回用户
    delete user.hash;
    return user;
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
      delete user.hash;
      // 返回user
      return user;
    } catch (error) {
      if (error.code === 'P2002') {
        throw new ForbiddenException('邮箱已存在');
      }
      throw error;
    }
  }
}
