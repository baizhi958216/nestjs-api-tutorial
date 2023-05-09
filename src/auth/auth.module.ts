import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrateGy } from './strategy';

@Module({
  imports: [JwtModule],
  controllers: [AuthController],
  providers: [AuthService, JwtStrateGy],
})
export class AuthModule {}
