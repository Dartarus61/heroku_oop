import { Module } from '@nestjs/common'
import { CommentService } from './comment.service'
import { CommentController } from './comment.controller'
import { SequelizeModule } from '@nestjs/sequelize'
import { Comment } from './comment.model'
import { UPost } from 'src/post/post.model'

@Module({
    providers: [CommentService],
    controllers: [CommentController],
    imports: [SequelizeModule.forFeature([Comment, UPost])],
})
export class CommentModule {}
