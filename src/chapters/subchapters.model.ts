import { ApiProperty } from '@nestjs/swagger'
import {
    BelongsTo,
    BelongsToMany,
    Column,
    DataType,
    ForeignKey,
    HasMany,
    HasOne,
    Model,
    Table,
} from 'sequelize-typescript'
import { UPost } from 'src/post/post.model'
import { Chapter } from './chapter.model'

@Table({ tableName: 'subchapt' })
export class SubChapt extends Model<SubChapt> {
    @ApiProperty({ example: 1, description: 'Уникальный идентификатор' })
    @Column({
        type: DataType.INTEGER,
        unique: true,
        autoIncrement: true,
        primaryKey: true,
    })
    id: number

    @ApiProperty({ example: 'JavaFX', description: 'Название подраздела' })
    @Column({ type: DataType.STRING, allowNull: false })
    name: string

    @HasMany(() => UPost)
    posts: UPost[]

    @ForeignKey(() => Chapter)
    @Column({ type: DataType.INTEGER, allowNull: false })
    chapterId: number

    @BelongsTo(() => Chapter)
    chapter: Chapter
}
