import { Body, Controller, Get, Param, Post } from '@nestjs/common'
import { ApiOperation, ApiParam, ApiResponse, ApiTags } from '@nestjs/swagger'
import { CreateRoleDto } from './dto/create-role.dto'
import { Role } from './role.model'
import { RoleService } from './role.service'

@ApiTags('Роли')
@Controller('role')
export class RoleController {
    constructor(private roleService: RoleService) {}

    @ApiOperation({ summary: 'Создание роли' })
    @ApiResponse({ status: 201, type: Role })
    @Post()
    create(@Body() dto: CreateRoleDto) {
        return this.roleService.createRole(dto)
    }

    @ApiOperation({ summary: 'Получение роли по параметру' })
    @ApiResponse({ status: 201, type: Role })
    @Get('/:value')
    getByValue(@Param('value') value: string) {
        return this.roleService.getRoleByValue(value)
    }

    @ApiOperation({ summary: 'Получение ролей' })
    @ApiResponse({ status: 201, type: [Role] })
    @Get('/all')
    GetAll() {
        return this.roleService.GetAll()
    }
}
