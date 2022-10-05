import { Body, Controller, Get, Post } from '@nestjs/common'
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger'
import { Chapter } from './chapter.model'
import { ChaptersService } from './chapters.service'
import { CreateChapterDto } from './dto/CreateChapter.dto'
import { CreateSubChapterDto } from './dto/CreateSubChapter.dto'
import { SubChapt } from './subchapters.model'

@ApiTags('Разделы и подразделы')
@Controller('chapters')
export class ChaptersController {
    constructor(private chapterService: ChaptersService) {}

    @ApiOperation({ summary: 'Создание раздела' })
    @ApiResponse({ status: 201, type: Chapter })
    @Post('/crch')
    CreateChapter(@Body() dto: CreateChapterDto) {
        return this.chapterService.CreateChapter(dto)
    }

    @ApiOperation({ summary: 'Создание подраздела' })
    @ApiResponse({ status: 201, type: SubChapt })
    @Post('/crsubch')
    CreateSubChapter(@Body() dto: CreateSubChapterDto) {
        return this.chapterService.CreateSubChapter(dto)
    }

    @ApiOperation({ summary: 'Получение всех разделов и их подразделов с вложенными статьями' })
    @ApiResponse({ status: 201, type: [Chapter] })
    @Get()
    GetAll() {
        return this.chapterService.getall()
    }
}
