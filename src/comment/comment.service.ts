import { Injectable } from '@nestjs/common'
import { InjectModel } from '@nestjs/sequelize'
import { UPost } from 'src/post/post.model'
import { SetComment } from './dto/comment.dto'

@Injectable()
export class CommentService {
    constructor(@InjectModel(UPost) private postRepository: typeof UPost) {}

    async setComment(dto: SetComment) {
        const NewComment = await this.postRepository.findOne({ where: { id: dto.postId } })
        await NewComment.$create('comments', { description: dto.ctx, userId: dto.userId })
        return NewComment
    }
}
