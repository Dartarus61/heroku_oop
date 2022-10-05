import { BelongsToMany, Column, DataType, HasMany, Model, Table } from 'sequelize-typescript'
import { Details } from './backup-details.model'

@Table({ tableName: 'history' })
export class History extends Model<History> {
    @Column({
        type: DataType.INTEGER,
        unique: true,
        autoIncrement: true,
        primaryKey: true,
    })
    id: number

    @Column({ type: DataType.STRING, allowNull: false })
    action: string

    @Column({ type: DataType.STRING, allowNull: false })
    table_name: string

    @Column({ type: DataType.DATE, allowNull: false })
    data: string

    @Column({ type: DataType.INTEGER, allowNull: false })
    idOfLine: number

    @Column({ type: DataType.BOOLEAN, allowNull: false })
    current: boolean

    @HasMany(() => Details)
    details: Details[]
}
