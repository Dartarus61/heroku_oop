import { ApiProperty } from '@nestjs/swagger'
import { IsNumber, IsString } from 'class-validator'

export class SetComment {
    @ApiProperty({ example: 1, description: 'ID статьи' })
    @IsNumber({}, { message: 'Должно быть числом' })
    readonly postId: number
    @ApiProperty({ example: 'Топ статья, автор крут, пили дальше!', description: 'Содержание комментария' })
    @IsString({ message: 'Должно быть строкой' })
    readonly ctx: string
    @ApiProperty({ example: 5, description: 'ID пользователя' })
    @IsNumber({}, { message: 'Должно быть числом' })
    readonly userId: number
}
