import {
  WebSocketGateway,
  WebSocketServer,
  OnGatewayConnection,
  OnGatewayDisconnect,
} from '@nestjs/websockets';
import { Server } from 'socket.io';
import { Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

const USER_ROOM_PREFIX = 'user:';

@WebSocketGateway({
  cors: { origin: '*' },
  namespace: '/',
})
export class NotificationsGateway
  implements OnGatewayConnection, OnGatewayDisconnect
{
  @WebSocketServer()
  server!: Server;

  private readonly logger = new Logger(NotificationsGateway.name);

  constructor(private readonly jwtService: JwtService) {}

  async handleConnection(client: { handshake: { auth?: { token?: string }; query?: { token?: string } }; id: string; join: (room: string) => void; disconnect: () => void }) {
    const token =
      client.handshake?.auth?.token ?? client.handshake?.query?.token;
    if (!token || typeof token !== 'string') {
      this.logger.warn(`Client ${client.id} connected without token`);
      client.disconnect();
      return;
    }
    try {
      const payload = await this.jwtService.verifyAsync(token);
      const userId = payload.userId;
      if (!userId) {
        client.disconnect();
        return;
      }
      const room = `${USER_ROOM_PREFIX}${userId}`;
      client.join(room);
      this.logger.log(`Client ${client.id} joined room ${room}`);
    } catch {
      this.logger.warn(`Client ${client.id} invalid token`);
      client.disconnect();
    }
  }

  handleDisconnect(client: { id: string }) {
    this.logger.log(`Client ${client.id} disconnected`);
  }

  emitToUser(userId: number, payload: unknown): void {
    const room = `${USER_ROOM_PREFIX}${userId}`;
    this.server.to(room).emit('notification', payload);
  }
}
