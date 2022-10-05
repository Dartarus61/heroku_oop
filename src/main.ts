import { NestFactory } from '@nestjs/core'
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger'
import { AppModule } from './app.module'
import { ValidationPipe } from './pipes/validation.pipe'

async function bootstrap() {
    const PORT = process.env.PORT || 8080
    const app = await NestFactory.create(AppModule)

    const config = new DocumentBuilder()
        .setTitle('OOP project')
        .setDescription('The backend Node API description')
        .setVersion('1.0.0')
        .addTag('Dartar')
        .build()
    const document = SwaggerModule.createDocument(app, config)
    SwaggerModule.setup('/api/docs', app, document)

    //app.useGlobalPipes(new ValidationPipe())

    await app.listen(PORT, () => console.log(`server started on ${process.env.PORT}`, process.env))
}
bootstrap()
