import { ApiProperty } from '@nestjs/swagger'
import { BelongsToMany, Column, DataType, HasMany, Model, Table } from 'sequelize-typescript'
import { UPost } from 'src/post/post.model'
import { Role } from 'src/role/role.model'
import { UserRoles } from 'src/role/user-roles.model'

interface UserCreationAttrs {
    email: string
    password: string
}

@Table({ tableName: 'users' })
export class User extends Model<User, UserCreationAttrs> {
    @ApiProperty({ example: '1', description: 'Уникальный идентификатор' })
    @Column({
        type: DataType.INTEGER,
        unique: true,
        autoIncrement: true,
        primaryKey: true,
    })
    id: number

    @ApiProperty({ example: 'user@mail.ru', description: 'Почтовый адрес' })
    @Column({ type: DataType.STRING, unique: true, allowNull: false })
    email: string

    @ApiProperty({ example: '12345678', description: 'Пароль' })
    @Column({ type: DataType.STRING, allowNull: false })
    password: string

    @ApiProperty({ example: 'Bob', description: 'Имя пользователя' })
    @Column({ type: DataType.STRING, allowNull: false })
    name: string

    @ApiProperty({ example: 'Clemente', description: 'Фамилия пользователя' })
    @Column({ type: DataType.STRING, allowNull: false })
    surname: string

    @Column({ type: DataType.BOOLEAN, defaultValue: false })
    isActivated: boolean

    @Column({ type: DataType.STRING, allowNull: true })
    acticationLink: string

    @ApiProperty({ example: '[USER]', description: 'Роли пользователя' })
    @BelongsToMany(() => Role, () => UserRoles)
    roles: Role[]

    @HasMany(() => UPost)
    posts: UPost[]
}
