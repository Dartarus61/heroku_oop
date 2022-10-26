import { HttpService } from '@nestjs/axios'
import { HttpException, HttpStatus, Injectable } from '@nestjs/common'
import { InjectModel } from '@nestjs/sequelize'
import { AxiosResponse } from 'axios'
import { Observable } from 'rxjs'
import { BackupService } from 'src/backup/backup.service'
import { createPreLogDto } from 'src/backup/dto/createPreLog.dto'
import { RoleService } from 'src/role/role.service'
import { ChangeRoleDto } from './dto/ChangeRole.dto'
import { CreateUserDto } from './dto/create_user.dto'
import { UpdateUserDto } from './dto/UpdateUser.dto'
import { User } from './user.model'
import * as uuid from 'uuid'
import { MailService } from 'src/mail/mail.service'

@Injectable()
export class UserService {
    constructor(
        @InjectModel(User)
        private userRepository: typeof User,
        private roleService: RoleService,
        private backupService: BackupService,
        private httpService: HttpService,
        private mailService: MailService
    ) {}

    async createUser(dto: CreateUserDto) {
        const user = await this.userRepository.create(dto)
        const role = await this.roleService.getRoleByValue('ADMIN')
        await user.$set('roles', [role.id])
        user.roles = [role]
        const acticationLink = uuid.v4()
        await user.update({ acticationLink })
        this.mailService.sendActivation(user.email, user.acticationLink)

        //this.create(log)
        //this.backupService.CreateLine(await this.backupService.createDto(log))
        return user
    }
    async addRole(dto: ChangeRoleDto) {
        const user = await this.userRepository.findByPk(dto.userId)
        const role = await this.roleService.getRoleByValue(dto.value)
        if (role && user) {
            await user.$add('roles', [role.id])
            return user
        }
        throw new HttpException('Пользователь или роль не найдена', HttpStatus.NOT_FOUND)
    }

    async getAll() {
        const users = await this.userRepository.findAll({ include: { all: true } })
        return users
    }

    async updateUser(dto: UpdateUserDto) {
        const user = await this.userRepository.findByPk(dto.id)
        if (user) {
            let log = {
                method: 'update',
                table_name: 'user',
                predto: user.toJSON(),
            }
            //this.backupService.CreateLine(await this.backupService.createDto(log))
            delete dto.id
            await user.update({ ...dto })
            return user
        }
    }

    async getUserByEmail(email: string) {
        const user = await this.userRepository.findOne({
            where: { email },
            include: { all: true },
        })
        return user
    }

    async getUserById(id: number) {
        const user = await this.userRepository.findByPk(id)
        if (user) return user
        throw new HttpException('пользователь не найден', HttpStatus.NOT_FOUND)
    }

    async getUserByLink(link: string) {
        const user = await this.userRepository.findOne({ where: { acticationLink: link } })
        if (!user) throw new HttpException('пользователь не найден', HttpStatus.NOT_FOUND)
        return user
    }

    async deleteUser(email: string) {
        const user = await this.getUserByEmail(email)
        await this.userRepository.destroy({ where: { id: user.id } })
    }
}
