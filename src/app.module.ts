import { Module } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'
import { UserModule } from './user/user.module'
import { AuthModule } from './auth/auth.module'
import { SequelizeModule } from '@nestjs/sequelize'
import { ServeStaticModule } from '@nestjs/serve-static'
import { User } from './user/user.model'
import { PostModule } from './post/post.module'
import * as path from 'path'
import { UPost } from './post/post.model'
import { RoleModule } from './role/role.module'
import { Role } from './role/role.model'
import { UserRoles } from './role/user-roles.model'
import { FilesModule } from './files/files.module'
import { CommentModule } from './comment/comment.module'
import { Comment } from './comment/comment.model'
import { BackupModule } from './backup/backup.module'
import { History } from './backup/backup-history.model'
import { Details } from './backup/backup-details.model'
import { ChaptersModule } from './chapters/chapters.module'
import { Chapter } from './chapters/chapter.model'
import { SubChapt } from './chapters/subchapters.model'
import { FileFolder } from './files/file.model'

@Module({
    imports: [
        ConfigModule.forRoot({
            envFilePath: `.env`,
        }),
        ServeStaticModule.forRoot({
            rootPath: path.resolve(__dirname, 'static'),
        }),
        SequelizeModule.forRoot(
            /*  dialect: 'postgres',
            host: process.env.DB_HOST,
            port: 5432,
            username: process.env.DB_USER ,
            password: process.env.DB_PASSWORD ,
            database: process.env.DB_NAME , */
            {
                uri: process.env.DATABASE_URL,
                models: [User, UPost, Role, UserRoles, Comment, History, Details, Chapter, SubChapt, FileFolder],
                autoLoadModels: true,
                sync: { alter: true },
                ssl: true,
                dialectOptions:{
                    rejectUnauthorized: false,
                    require: true,
                }
            }
        ),
        UserModule,
        AuthModule,
        PostModule,
        RoleModule,
        FilesModule,
        CommentModule,
        BackupModule,
        ChaptersModule,
    ],
})
export class AppModule {}
