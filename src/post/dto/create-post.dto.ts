import { ApiProperty } from '@nestjs/swagger'
import { IsNumber, IsString } from 'class-validator'

export class CreatePostDto {
    @ApiProperty({ example: 'hello world', description: 'Текст статьи' })
    @IsString({ message: 'Должно быть строкой' })
    readonly description: string
    @ApiProperty({ example: 'JAVA FX', description: 'Название статьи' })
    @IsString({ message: 'Должно быть строкой' })
    readonly title: string
    @ApiProperty({ example: 'Java', description: 'Название раздела' })
    @IsString({ message: 'Должно быть строкой' })
    readonly chapter: string
    @ApiProperty({ example: 'JavaFX', description: 'Название подраздела' })
    @IsString({ message: 'Должно быть строкой' })
    readonly subsection: string
    @ApiProperty({ example: 1, description: 'ID пользователя' })
    @IsString({ message: 'Должно быть строкой' })
    readonly userId: number
}
