import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common'
import { Roles } from 'src/auth/roles-auth.decorator'
import { RolesGuard } from 'src/auth/roles.guard'
import { BackupService } from './backup.service'
import { createPreLogDto } from './dto/createPreLog.dto'

@Controller('backup')
export class BackupController {
    constructor(private backupService: BackupService) {}

    @Get()
    GetMy() {
        return this.backupService.GetLog()
    }

    @Post('/log')
    async LogThis(@Body() dto: createPreLogDto) {
        console.log(123)
        const logdto = await this.backupService.createDto(dto)
        console.log(logdto);
        
        return this.backupService.CreateLine(logdto)
    }
}
