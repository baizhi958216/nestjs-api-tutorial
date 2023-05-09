import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../src/prisma/prisma.service';
import { EditUserDto } from './dto';

@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}

  async editUser(userid: number, dto: EditUserDto) {
    const user = await this.prisma.user.update({
      where: {
        id: userid,
      },
      data: {
        ...dto,
      },
    });
    delete user.hash;

    return user;
  }
}
