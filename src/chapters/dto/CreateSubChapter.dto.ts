import { ApiProperty } from '@nestjs/swagger'
import { IsNumber, IsString } from 'class-validator'

export class CreateSubChapterDto {
    @ApiProperty({ example: 'Java', description: 'название подраздела' })
    @IsString({ message: 'Должно быть строкой' })
    readonly name: string
    @ApiProperty({ example: 5, description: 'ID раздела' })
    @IsNumber({}, { message: 'Должно быть числом' })
    readonly chapterId: number
}
