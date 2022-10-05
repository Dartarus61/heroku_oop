import { ApiProperty } from '@nestjs/swagger'
import { IsNumber, IsString } from 'class-validator'

export class ChangeRoleDto {
    @ApiProperty({ example: 'CREATOR', description: 'Новая роль' })
    @IsString({ message: 'Должно быть строкой' })
    readonly value: string
    @ApiProperty({ example: 5, description: 'ID пользователя' })
    @IsNumber({}, { message: 'Должно быть числом' })
    readonly userId: number
}
