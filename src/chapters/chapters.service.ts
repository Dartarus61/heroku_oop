import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/sequelize';
import { Chapter } from './chapter.model';
import { CreateChapterDto } from './dto/CreateChapter.dto';
import { CreateSubChapterDto } from './dto/CreateSubChapter.dto';
import { SubChapt } from './subchapters.model';

@Injectable()
export class ChaptersService {
    constructor(@InjectModel(Chapter) private ChapterRepository:typeof Chapter,
    @InjectModel(SubChapt)private SubChapterRepository:typeof SubChapt){}

    async CreateChapter(dto:CreateChapterDto){
        const chapter = await this.ChapterRepository.create({...dto})
        return chapter
    }

    async CreateSubChapter(dto: CreateSubChapterDto) {
        const mainChapter = await this.ChapterRepository.findByPk(dto.chapterId)
        if (mainChapter) {
            console.log(mainChapter);
            /* const sub= await this.SubChapterRepository.create({name:dto.name})
            mainChapter.$add('subChapts',sub) */
            await mainChapter.$create('subChapt',{...dto})
            return mainChapter
        }
        throw new HttpException('Данный модуль не найден',HttpStatus.NOT_FOUND)
    }

    async GetChupterByName(name:string) {
        const chupter = await this.ChapterRepository.findOne({where:{name}, include:[SubChapt]})
        if (chupter) {
            return chupter
        }
        throw new HttpException('Раздел не найден', HttpStatus.NOT_FOUND)
    }

    async GetSubByName(name:string) {
        const subchupter = await this.SubChapterRepository.findOne({where:{name}, include:[{all:true}]})
        if (subchupter) {
            return subchupter
        }
        throw new HttpException('Подраздел не найден', HttpStatus.NOT_FOUND)
    }

    async getall(){
        const chapt = await this.ChapterRepository.findAll({include:[{all:true}]})
        return chapt
    }

}
