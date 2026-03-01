import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma.service';

@Injectable()
export class FoldersService {
  constructor(private prisma: PrismaService) {}

  /**
   * TODO: Add folder CRUD and sync from mailbox providers.
   */
}
