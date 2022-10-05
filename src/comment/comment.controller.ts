import { Body, Controller, Post } from '@nestjs/common'
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger'
import { Roles } from 'src/auth/roles-auth.decorator'
import { Comment } from './comment.model'
import { CommentService } from './comment.service'
import { SetComment } from './dto/comment.dto'

@ApiTags('Комментарии')
@Controller('comment')
export class CommentController {
    constructor(private commentService: CommentService) {}

    @ApiOperation({ summary: 'Создание статьи' })
    @ApiResponse({ status: 201, type: Comment })
    @Roles('USER', 'ADMIN')
    @Post('/setcom')
    SetComment(@Body() dto: SetComment) {
        return this.commentService.setComment(dto)
    }
}
