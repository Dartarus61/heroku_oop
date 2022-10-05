import { ApiProperty } from '@nestjs/swagger'
import { IsNumber, IsString } from 'class-validator'

export class GetGroupOffers {
    @ApiProperty({ example: 'Java', description: 'Название раздела' })
    @IsString({ message: 'Должно быть строкой' })
    readonly chapter: string
    @ApiProperty({ example: 1, description: 'ID пользователя' })
    @IsNumber({}, { message: 'Должно быть числом' })
    readonly userId: number
}
