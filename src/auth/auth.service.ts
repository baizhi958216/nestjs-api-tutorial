import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  signin() {
    return { msg: 'I have signed in' };
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
