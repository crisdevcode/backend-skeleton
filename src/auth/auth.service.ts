import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import { Model } from 'mongoose';

import * as bcryptjs from 'bcryptjs';

import { User } from './entities/user.entity';

import { CreateUserDto, UpdateAuthDto, LoginDto, RegisterUserDto } from './dto/index';

import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService
  ){}

  async create(createUserDto: CreateUserDto): Promise<User> {

    try {

      // Extract password, email and name
      const { password, ...userData } = createUserDto;
      
      // Build user and encrypt password
      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData
      });
      
      // Save user in database
      await newUser.save();

      const { password: _, ...user } = newUser.toJSON();

      return user;

    } catch (error) {
      if(error.code === 11000) {
        throw new BadRequestException(`${ createUserDto.email } already exists!`);
      }

      throw new InternalServerErrorException('Something terrible happen!!')
    }
    
  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    // Extract email and password
    const { email, password } = loginDto;

    // Find user in database
    const user = await this.userModel.findOne({ email });

    // Validate email existence
    if(!user) {
      throw new UnauthorizedException('Not valid credentials - email');
    }

    // Validate if the password matches
    if(!bcryptjs.compareSync(password, user.password)) { 
      throw new UnauthorizedException('Not valid credentials - password');
    }

    const { password: _, ...rest} = user.toJSON();

    return {
      user: rest,
      token: this.getJwtToken({ id: user.id })
    }
  }

  async register(registerDto: RegisterUserDto): Promise<LoginResponse> {

    const user = await this.create(registerDto);

    return {
      user: user,
      token: this.getJwtToken({ id: user._id })
    } 
  }

  async findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById(id: String) {
    const user = await this.userModel.findById(id);
    const { password, ...rest } = user.toJSON();
    return rest;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken(payload: JwtPayload) {
    const token = this.jwtService.sign(payload);
    return token;
  }
}
