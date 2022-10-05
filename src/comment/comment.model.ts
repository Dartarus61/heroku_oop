import { ApiProperty } from '@nestjs/swagger'
import { BelongsTo, BelongsToMany, Column, DataType, ForeignKey, HasMany, Model, Table } from 'sequelize-typescript'
import { UPost } from 'src/post/post.model'
import { User } from 'src/user/user.model'

interface PostCreationAttrs {
    description: string
    economic: string
    area_of_improvement: string
    filePath: string
}

@Table({ tableName: 'comments' })
export class Comment extends Model<Comment> {
    @ApiProperty({ example: '1', description: 'Уникальный идентификатор' })
    @Column({
        type: DataType.INTEGER,
        unique: true,
        autoIncrement: true,
        primaryKey: true,
    })
    id: number

    @ApiProperty({ example: 'Автор хорош, давай дальше!', description: 'Содержание комментария' })
    @Column({ type: DataType.STRING, allowNull: false })
    description: string

    @ApiProperty({ example: 5, description: 'ID пользователя, который написал комментарий' })
    @Column({ type: DataType.INTEGER, allowNull: false })
    userId: number

    @ForeignKey(() => UPost)
    @Column({ type: DataType.INTEGER })
    postId: number

    @BelongsTo(() => UPost)
    post: UPost
}
