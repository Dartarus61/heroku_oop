export class CreateLineDto {
    readonly action: string
    readonly table_name: string
    readonly data: string
    column_name: string
    value: JSON
}
