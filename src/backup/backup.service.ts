import { Injectable } from '@nestjs/common'
import { InjectModel } from '@nestjs/sequelize'
import { Details } from './backup-details.model'
import { History } from './backup-history.model'
import { CreateLineDto } from './dto/CreateLine.dto'
import { createPreLogDto } from './dto/createPreLog.dto'

@Injectable()
export class BackupService {
    constructor(
        @InjectModel(History)
        private HistoryRepository: typeof History,
        @InjectModel(Details) private DetailsRepository: typeof Details
    ) {}

    async GetLog() {
        const log = await this.HistoryRepository.findAll({ include: [Details] })
        return log
    }

    async CreateLine(dto: CreateLineDto) {
        console.log('loggggggggggggg')

        const my_details = {
            column_name: dto.column_name,
            value: dto.value,
        }
        console.log(my_details)
        const str = JSON.stringify(my_details.value)
        let id: number = null
        for (const key in my_details.value) {
            if (key == 'id') id = my_details.value[key]
        }
        delete dto.value
        delete dto.column_name
        const line = await this.HistoryRepository.create({ ...dto, current: true, idOfLine: id })
        const logLine = await this.HistoryRepository.findOne({ where: { id: line.id - 1 } })
        if (logLine) logLine.update({ current: false })
        let column_name_mas = my_details.column_name.split(',')
        column_name_mas.pop()
        for (let index = 0; index < column_name_mas.length; index++) {
            let details = await this.DetailsRepository.create({
                column_name: column_name_mas[index],
                value: { ...my_details.value },
            })
            await line.$add('details', details)
        }
        console.log(typeof line);
        
        return line
    }

    async createDto(/* method: string, table_name: string, predto, columns?, */ dto?: createPreLogDto) {
        console.log('123123123231231')

        let str: string = ''
        let time: string
        if (dto.method == 'create') {
            for (const key in dto.predto) {
                str += `${key},`
            }
            time = dto.predto.createdAt
        } else if (dto.method == 'update') {
            for (const key in dto.columns) {
                str += `${key},`
            }
            time = dto.predto.updatedAt
        }
        let full_dto = {
            action: dto.method,
            table_name: dto.table_name,
            data: time,
            column_name: str,
            value: dto.predto,
        }
        return full_dto
    }

    async getAll() {
        const log = await this.HistoryRepository.findAll({ include: [Details] })
        return log
    }
}
