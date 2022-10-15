import { ApiProperty } from '@nestjs/swagger'
import { IsNumber, IsString } from 'class-validator'

export class CreateChapterDto {
    @ApiProperty({ example: 'Java', description: 'название раздела' })
    @IsString({ message: 'Должно быть строкой' })
    readonly name: string
    @ApiProperty({ example: 3, description: 'Родитель данного раздела' })
    // @IsNumber({ allowNaN: true }, { message: 'Должно быть числом' })
    readonly idParent?: number
}
