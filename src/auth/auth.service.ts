import { HttpException, HttpStatus, Injectable, UnauthorizedException } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { UserService } from 'src/user/user.service'
import { CreateUserDto } from '../user/dto/create_user.dto'
import { ResetPassDto } from './dto/respass.dto'
import * as bcrypt from 'bcrypt'
import { User } from 'src/user/user.model'
import { LoginDto } from './dto/login.dto'

@Injectable()
export class AuthService {
    constructor(private userService: UserService, private jwtService: JwtService) {}

    async registration(userDto: CreateUserDto) {
        const candidate = await this.userService.getUserByEmail(userDto.email)
        if (candidate) {
            throw new HttpException('Пользователь с таким email существует', HttpStatus.BAD_REQUEST)
        }
        const hashPassword = await bcrypt.hash(userDto.password, 5)
        const user = await this.userService.createUser({ ...userDto, password: hashPassword })
        return this.generateToken(user)
    }

    private async generateToken(user: User) {
        const payload = { email: user.email, id: user.id, roles: user.roles }
        return {
            token: this.jwtService.sign(payload, { secret: process.env.PRIVATE_KEY }),
            user: {
                id: user.id,
                email: user.email,
                isActivated: user.isActivated,
            },
        }
    }

    private async validateUser(userDto: LoginDto) {
        const user = await this.userService.getUserByEmail(userDto.email)
        if (!user) throw new HttpException('Пользователь с таким емаил не найден', HttpStatus.BAD_REQUEST)
        if (user.isActivated == false) throw new HttpException('Пользователь не подтвердил почту', HttpStatus.FORBIDDEN)
        const passwordEquals = await bcrypt.compare(userDto.password, user.password)
        if (user && passwordEquals) {
            return user
        }
        throw new UnauthorizedException({ message: 'Некорректный емайл или пароль' })
    }

    async login(userDto: LoginDto) {
        console.log(userDto)

        const user = await this.validateUser(userDto)
        return this.generateToken(user)
    }

    async reset(dto: ResetPassDto) {
        const user = await this.userService.getUserByEmail(dto.email)
        if (!user) throw new HttpException('Пользователь с таким емаил не найден', HttpStatus.BAD_REQUEST)
        const isEqual = await bcrypt.compare(dto.newpass, user.password)
        if (isEqual) throw new HttpException('Пароли не должны совпадать', HttpStatus.UNAUTHORIZED)
        const NewPass = await bcrypt.hash(dto.newpass, 3)
        await user.update({ password: NewPass })
        return 'Пароль сменен'
    }

    async checkIt(authHeader: string) {
        console.log(authHeader)

        const bearer = authHeader.split(' ')[0]
        const token = authHeader.split(' ')[1]

        if (bearer !== 'Bearer' || !token) {
            throw new UnauthorizedException({ message: 'Пользователь не авторизован' })
        }
        let tokenVerify: User
        try {
            tokenVerify = this.jwtService.verify(token, { secret: process.env.PRIVATE_KEY })
        } catch (error) {
            throw new HttpException('Ошибка авторазации', HttpStatus.BAD_REQUEST)
        }
        const user = await this.userService.getUserById(tokenVerify.id)
        return this.generateToken(user)
    }

    async activate(value: string) {
        const user = await this.userService.getUserByLink(value)
        user.update({ isActivated: true })
        return user
    }

    async logout(token: string) {}
}
