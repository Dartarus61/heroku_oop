import { Body, Controller, Get, Param, Post, UseGuards } from '@nestjs/common'
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger'
import { Roles } from 'src/auth/roles-auth.decorator'
import { RolesGuard } from 'src/auth/roles.guard'
import { BackupService } from 'src/backup/backup.service'
import { ChangeRoleDto } from './dto/ChangeRole.dto'
import { CreateUserDto } from './dto/create_user.dto'
import { UpdateUserDto } from './dto/UpdateUser.dto'
import { User } from './user.model'
import { UserService } from './user.service'
@ApiTags('Пользователи')
@Controller('user')
export class UserController {
    constructor(private UserService: UserService, private BackupService: BackupService) {}

    @ApiOperation({ summary: 'Создание пользователя' })
    @ApiResponse({ status: 201, type: User })
    @UseGuards(RolesGuard)
    @Roles('USER')
    @Post('/create')
    create(@Body() Dto: CreateUserDto) {
        return this.UserService.createUser(Dto)
    }

    @Get('/activ/:value')
    activation(@Param('value') value:string) {
        return this.UserService.activate(value)
    }


    @ApiOperation({ summary: 'Поиск пользователя по почте' })
    @ApiResponse({ status: 200, type: User })
    @UseGuards(RolesGuard)
    @Roles('USER')
    @Post('/byemail')
    GetUserByEmail(@Body('email') email: string) {
        return this.UserService.getUserByEmail(email)
    }

    @ApiOperation({ summary: 'Выдать роль' })
    @ApiResponse({ status: 200 })
    @UseGuards(RolesGuard)
    @Roles('ADMIN')
    @Post('/addrole')
    ChangeRole(@Body() dto: ChangeRoleDto) {
        return this.UserService.addRole(dto)
    }

    @ApiOperation({ summary: 'Изменение данных пользователя' })
    @ApiResponse({ status: 200, type: User })
    @UseGuards(RolesGuard)
    @Roles('USER', 'ADMIN')
    @Post('/updata')
    ChangeData(@Body() dto: UpdateUserDto) {
        return this.UserService.updateUser(dto)
    }

    @ApiOperation({ summary: 'Получить всех пользователей' })
    @ApiResponse({ status: 200, type: [User] })
    @UseGuards(RolesGuard)
    @Roles('ADMIN')
    @Get('/all')
    AllPeople() {
        return this.UserService.getAll()
    }
}
