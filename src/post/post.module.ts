import { forwardRef, Module } from '@nestjs/common'
import { JwtModule } from '@nestjs/jwt'
import { SequelizeModule } from '@nestjs/sequelize'
import { AuthModule } from 'src/auth/auth.module'
import { Chapter } from 'src/chapters/chapter.model'
import { ChaptersModule } from 'src/chapters/chapters.module'
import { FilesModule } from 'src/files/files.module'
import { User } from 'src/user/user.model'
import { UserModule } from 'src/user/user.module'
import { PostController } from './post.controller'
import { UPost } from './post.model'
import { PostService } from './post.service'

@Module({
    controllers: [PostController],
    providers: [PostService],
    imports: [
        forwardRef(()=>ChaptersModule),
        SequelizeModule.forFeature([User, UPost, Chapter]),
        FilesModule,
        UserModule,
        JwtModule,
        AuthModule,
    ],
    exports: [PostService],
})
export class PostModule {}
