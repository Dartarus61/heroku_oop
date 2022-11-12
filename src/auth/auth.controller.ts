import { Body, Controller, Get, Param, Post, Req } from '@nestjs/common'
import { AuthService } from './auth.service'
import { CreateUserDto } from '../user/dto/create_user.dto'
import { ResetPassDto } from './dto/respass.dto'
import { LoginDto } from './dto/login.dto'
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger'
import { User } from 'src/user/user.model'
import { Request } from 'express'

@ApiBearerAuth('JWT')
@ApiTags('Авторизация')
@Controller('auth')
export class AuthController {
    constructor(private AuthService: AuthService) {}

    @ApiOperation({ summary: 'Создание пользователя' })
    @ApiResponse({ status: 201, type: User })
    @Post('/registration')
    reg(@Body() dto: CreateUserDto) {
        return this.AuthService.registration(dto)
    }

    @ApiOperation({ summary: 'Авторизация в аккаунт' })
    @ApiResponse({ status: 201, type: User })
    @Post('/login')
    login(@Body() dto: LoginDto) {
        return this.AuthService.login(dto)
    }

    @ApiOperation({ summary: 'Выход из аккаунта' })
    @ApiResponse({ status: 201, type: User })
    @Post('/logout')
    logout(@Body('RefreshToken') token: string) {
        return this.AuthService.logout(token)
    }

    @ApiOperation({ summary: 'Сброс пароля' })
    @ApiResponse({ status: 201, type: User })
    @Post('/reset')
    ResetPass(@Body() dto: ResetPassDto) {
        return this.AuthService.reset(dto)
    }

    @ApiOperation({ summary: 'Стартовая страница' })
    @ApiResponse({ status: 201, type: User })
    @Post('/refresh')
    refresh(@Req() req: Request) {
        console.log(req.headers)

        return this.AuthService.checkIt(req.headers.authorization)
    }

    @Get('/activ/:value')
    activation(@Param('value') value: string) {
        return this.AuthService.activate(value)
    }
    
    @Get('/refresh')
  refresh(@Headers("Authorization") authorization: string) {
    return this.authService.refresh(authorization);
  }
}
