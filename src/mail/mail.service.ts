import { MailerService } from '@nestjs-modules/mailer';
import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { UserService } from 'src/user/user.service';

@Injectable()
export class MailService {
    constructor(private readonly mailerService: MailerService) {}
    
     sendActivation(email:string,link:string): void {
        const finLink='http://'+process.env.API_URL+link
        this.mailerService
          .sendMail({
            to: `${email}`, // list of receivers
            from: 'project.oop@mail.ru', // sender address
            subject: 'Подтверждение почты ✔', // Subject line
            html:
            `<div>
                <style>
                    a{
                        color: blue
                    }
                </style>
                <h1> Для подтверждения смены пароля перейдите по ссылке</h1>
                <a class="blue" href="${finLink}">${finLink}</a>
            </div>`, // HTML body content
          })
          .then(() => {         
          })
          .catch((e) => {
            console.log(e);
            
            throw new HttpException('Ошибка отправления сообщения',HttpStatus.BAD_REQUEST)
          });
      }
}
