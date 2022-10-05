import { Module } from '@nestjs/common'
import { SequelizeModule } from '@nestjs/sequelize'
import { User } from 'src/user/user.model'
import { RoleController } from './role.controller'
import { Role } from './role.model'
import { RoleService } from './role.service'
import { UserRoles } from './user-roles.model'

@Module({
    controllers: [RoleController],
    providers: [RoleService],
    imports: [SequelizeModule.forFeature([Role, User, UserRoles])],
    exports: [RoleService],
})
export class RoleModule {}
