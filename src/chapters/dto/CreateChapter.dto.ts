import { ApiProperty } from '@nestjs/swagger'
import { IsString } from 'class-validator'

export class CreateChapterDto {
    @ApiProperty({ example: 'Java', description: 'название раздела' })
    @IsString({ message: 'Должно быть строкой' })
    readonly name: string
}
