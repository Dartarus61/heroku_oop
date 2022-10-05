import { Module } from '@nestjs/common';
import { ChaptersService } from './chapters.service';
import { ChaptersController } from './chapters.controller';
import { SequelizeModule } from '@nestjs/sequelize';
import { Chapter } from './chapter.model';
import { SubChapt } from './subchapters.model';

@Module({
  providers: [ChaptersService],
  controllers: [ChaptersController],
  imports:[SequelizeModule.forFeature([Chapter,SubChapt])],
  exports:[ChaptersService]
})
export class ChaptersModule {}
