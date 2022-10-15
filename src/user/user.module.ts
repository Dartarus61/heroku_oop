import { HttpModule } from '@nestjs/axios'
import { forwardRef, Module } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { SequelizeModule } from '@nestjs/sequelize'
import { AuthModule } from 'src/auth/auth.module'
import { BackupModule } from 'src/backup/backup.module'
import { MailModule } from 'src/mail/mail.module'
import { UPost } from 'src/post/post.model'
import { Role } from 'src/role/role.model'
import { RoleModule } from 'src/role/role.module'
import { UserRoles } from 'src/role/user-roles.model'
import { UserController } from './user.controller'
import { User } from './user.model'
import { UserService } from './user.service'

@Module({
    controllers: [UserController],
    providers: [UserService],
    exports: [UserService],
    imports: [
        SequelizeModule.forFeature([User, Role, UserRoles, UPost]),
        RoleModule,
        BackupModule,
        MailModule,
        forwardRef(() => AuthModule),
        
        HttpModule.register({
            timeout: 5000,
            maxRedirects: 5,
        }),
    ],
})
export class UserModule {}
