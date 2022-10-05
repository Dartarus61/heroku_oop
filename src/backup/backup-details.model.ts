import { BelongsTo, Column, DataType, ForeignKey, Model, Table } from 'sequelize-typescript'
import { History } from './backup-history.model'

@Table({ tableName: 'details' })
export class Details extends Model<Details> {
    @Column({
        type: DataType.INTEGER,
        unique: true,
        autoIncrement: true,
        primaryKey: true,
    })
    id: number

    @Column({ type: DataType.STRING, allowNull: false })
    column_name: string

    @Column({ type: DataType.JSON, allowNull: false })
    value: JSON

    @ForeignKey(() => History)
    @Column({ type: DataType.INTEGER })
    historyId: number

    @BelongsTo(() => History)
    history: History
}
