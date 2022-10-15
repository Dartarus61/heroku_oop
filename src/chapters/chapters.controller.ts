import { Body, Controller, Get, HttpStatus, Param, Post } from '@nestjs/common'
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger'
import { UPost } from 'src/post/post.model'
import { PostService } from 'src/post/post.service'
import { Chapter } from './chapter.model'
import { ChaptersService } from './chapters.service'
import { CreateChapterDto } from './dto/CreateChapter.dto'
import { CreateSubChapterDto } from './dto/CreateSubChapter.dto'

@ApiTags('Разделы и подразделы')
@Controller('chapters')
export class ChaptersController {
    constructor(private chapterService: ChaptersService, private postService: PostService) {}

    @ApiOperation({ summary: 'Создание раздела' })
    @ApiResponse({ status: 201, type: Chapter })
    @Post('/crch')
    CreateChapter(@Body() dto: CreateChapterDto) {
        return this.chapterService.CreateChapter(dto)
    }

    @ApiOperation({ summary: 'Главы и их подглавы' })
    @ApiResponse({ status: HttpStatus.CREATED, type: [Chapter] })
    @Get('/menu')
    GetMenu() {
        return this.chapterService.GetMenu()
    }

    @ApiOperation({ summary: 'Получение всех статей из подраздела' })
    @ApiResponse({ status: HttpStatus.OK, type: [UPost] })
    @Get('/:value')
    GetPosts(@Param('value') id: number) {
        return this.postService.getPostBySubChapters(id)
    }
    //TODO:Проверить работу метода
}
