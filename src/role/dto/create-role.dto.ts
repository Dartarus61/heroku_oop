import { ApiProperty } from '@nestjs/swagger'
import { IsString } from 'class-validator'

export class CreateRoleDto {
    @ApiProperty({ example: 'CREATOR', description: 'Роль' })
    @IsString({ message: 'Должно быть строкой' })
    readonly value: string
    @ApiProperty({ example: 'Может создавать статьи', description: 'Описание роли' })
    @IsString({ message: 'Должно быть строкой' })
    readonly description: string
}
