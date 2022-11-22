#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<pthread.h>
#include<fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/poll.h>
#include<string.h>
#include <sys/epoll.h>
#include<error.h>
#include<errno.h>
#include <dirent.h>
#include<arpa/inet.h>
#include<math.h>


//#define max(a,b) 
#define max(a, b) (((a) > (b)) ? (a) : (b))
#define  MAXS 1024  //最大监听数量
#define  BUFFLEN 1024 //buf大小
#define  DF_SERV_PORT 50000 //默认服务器监听端口
#define  MAX_KEYFILE_SIZE  4096  //最大密钥文件大小，当密钥文件大于最大限制时，不再填充密钥
#define  KEY_CREATE_RATE  128  //密钥每秒生成长度
#define  KEY_UNIT_SIZE    4   //密钥基本存储单位4字节
#define  KEY_RATIO       100    //SA密钥与会话密钥的比值
#define  KEY_FILE   "/home/keyfile.kf"   //密钥文件
#define  REMOTE_IPADDR "127.0.0.1"   //对方服务器的ip地址
#define  INIT_KEYD   10000 //初始密钥派生参数
#define  up_index  2  //派生增长因子
#define  down_index  0.1  //派生减少因子


pthread_rwlock_t keywr;
bool key_sync_flag, skey_sync_flag;  //两种密钥同步标志，一种用于供应sa协商，一种用于加密的会话密钥
int delkeyindex, keyindex, sekeyindex, sdkeyindex;  //密钥索引，用于删除过期密钥，标识当前的sa密钥,加密密钥，解密密钥
int encrypt_flag, decrypt_flag;  //加密密钥以及解密密钥的对应关系，0标识加密密钥，1标识解密密钥
int SERV_PORT;  //服务器监听端口
int cur_ekeyd, next_ekeyd, cur_dkeyd, next_dkeyd;   //记录当前的密钥派生参数和下一个密钥派生参数
int ekey_sindex, dkey_sindex;   //记录一个加解密密钥syn==1的数据包对应的密钥索引
char raw_dkey[64], raw_ekey[64], prived_dkey[64],prived_ekey[64];  //记录原始量子密钥和派生密钥

struct s_info {
	struct sockaddr_in  addr;
	int connfd;
};
int get_line(int cfd, char* buf, int size)
{
	int i = 0;
	char c = '\0';
	int n;
	while ((i < size - 1) && (c != '\n')) {
		n = recv(cfd, &c, 1, 0);
		if (n > 0) {
			if (c == '\r') {
				n = recv(cfd, &c, 1, MSG_PEEK);
				if ((n > 0) && (c == '\n')) {
					recv(cfd, &c, 1, 0);
				}
				else {
					c = '\n';
				}
			}
			buf[i] = c;
			i++;
		}
		else {
			c = '\n';
		}
	}
	buf[i] = '\0';

	if (-1 == n)
		i = n;

	return i;
}
void discon(int fd, int epfd) {
	int ret = epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
	if (ret < 0) {
		perror("EPOLL_CTL_DEL error...\n");
		exit(1);
	}
	close(fd);

}
void do_crecon(int fd,int epfd) {
	struct sockaddr_in cli_addr;
	char cli_ip[16];
	int client_addr_size,ret;
	struct epoll_event tep;
	int ar = accept(fd, (struct sockaddr_in*)&cli_addr, &client_addr_size);
	printf("ip address is: %s,port is: %d\n", inet_ntop(AF_INET, &cli_addr.sin_addr.s_addr, cli_ip, sizeof(cli_ip)),
		ntohs(cli_addr.sin_port));
	//设置ar socket非阻塞
	int flag = fcntl(ar, F_GETFL);
	flag |= O_NONBLOCK;
	fcntl(ar, F_SETFL, flag);
	//事件赋值
	tep.events = EPOLLIN|EPOLLET;
	tep.data.fd = ar;

	//事件上树
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, ar, &tep);
	if (ret == -1) {
		perror("epoll_ctl_add error!\n");
		exit(1);
	}
}


//发起连接 
void con_serv(int *fd,const char* src, int port) {
	int  ret,cr;
	struct sockaddr_in serv_addr, cli_addr;
	socklen_t client_addr_size;

	*fd = socket(AF_INET, SOCK_STREAM, 0);
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(SERV_PORT);
	inet_pton(AF_INET, src, &serv_addr.sin_addr.s_addr);

	cr = connect(*fd, &serv_addr, sizeof(serv_addr)); //连接对方服务器
	if (cr < 0) {
		perror("key_sync connect error!\n");
		return false;
	}
}
//加解密密钥对应关系同步
bool key_index_sync() {
	encrypt_flag = 0;
	decrypt_flag = 1;
	char buf[BUFFLEN], rbuf[BUFFLEN];
	int fd,ret, tencrypt_index,tdecrypt_index;

	con_serv(&fd, REMOTE_IPADDR, SERV_PORT); //连接对方服务器

	sprintf(buf, "kisync %d %d\n", encrypt_flag, decrypt_flag);
	send(fd, buf, strlen(buf), 0);

	ret= read(fd, rbuf, sizeof(rbuf));
	sscanf(rbuf, "%[^ ] %d %d", &tencrypt_index, &tdecrypt_index);
	close(fd);
	if (tencrypt_index == decrypt_flag && tdecrypt_index == encrypt_flag) {
		//close(fd);
		return true;
	}

	return false;
}
//密钥同步,本地与远端服务器建立连接同步密钥偏移
bool key_sync() {
	
	int fd,ret;
	char buf[BUFFLEN],rbuf[BUFFLEN], method[32];
	//struct sockaddr_in serv_addr, cli_addr;
	//socklen_t client_addr_size;
	sprintf(buf, "keysync %d %d %d %d\n", delkeyindex, keyindex, sekeyindex, sdkeyindex);
	

	con_serv(&fd, REMOTE_IPADDR, SERV_PORT); //连接对方服务器

	//write(fd, "FUCK\n", 5);
	ret = send(fd, buf, strlen(buf), 0);
	if (ret < 0) {
		perror("key_sync connect error!\n");
		return false;
	}
	ret = read(fd, rbuf, sizeof(rbuf));
	//n = get_line(fd, buf, BUFFLEN);
	int tdelkeyindex, tkeyindex, tsekeyindex, tsdkeyindex;
	sscanf(rbuf, "%[^ ] %d %d %d %d", method, &tdelkeyindex, &tkeyindex, &tsekeyindex, &tsdkeyindex);
	delkeyindex = max(tdelkeyindex, delkeyindex);
	keyindex = max(tkeyindex, keyindex);
	sekeyindex = max(tsekeyindex, sekeyindex);
	sdkeyindex = max(tsdkeyindex, sdkeyindex);
	close(fd);
	return true;
}

//密钥派生参数协商
bool derive_sync() {
	int fd, ret,tmp_keyd;
	char buf[BUFFLEN],rbuf[BUFFLEN], method[32];
	//通过密钥余量判断接下来的密钥派生参数
	if (sdkeyindex < 0.3 * MAX_KEYFILE_SIZE / KEY_UNIT_SIZE * 1 / 2 * (KEY_RATIO - 2) / KEY_RATIO) {
		tmp_keyd =(int) cur_ekeyd * up_index;
	}
	else if (sdkeyindex > 0.7 * MAX_KEYFILE_SIZE / KEY_UNIT_SIZE * 1 / 2 * (KEY_RATIO - 2) / KEY_RATIO) {
		tmp_keyd = (int)cur_ekeyd * (1 - down_index);
	}
	else {
		tmp_keyd = cur_ekeyd;
	}
	sprintf(buf, "desync %d", tmp_keyd);

	con_serv(&fd, REMOTE_IPADDR, SERV_PORT); //连接对方服务器
	ret = send(fd, buf, strlen(buf), 0);
	if (ret < 0) {
		perror("derive_sync connect error!\n");
		return false;
	}
	ret = read(fd, rbuf, sizeof(rbuf));
	int r_keyd;
	sscanf(rbuf, "%[^ ] %d", method, &r_keyd);
	close(fd);
	if (tmp_keyd == r_keyd) {
		next_ekeyd = tmp_keyd;

		return true;
	}
	
	return false;
}
//读取本地密钥
void readkey(const char* buf, const char key_type, const char* keylen) {
	int len = atoi(keylen);
	char* pb = buf;
	pthread_rwlock_rdlock(&keywr);  //上读锁
	FILE* fp = fopen(KEY_FILE, "r");
	if (fp == NULL) {
		perror("open keyfile error!\n");
	}
	else {
		if (key_type == '0') {  //加密密钥
			fseek(fp, sekeyindex * KEY_UNIT_SIZE, SEEK_SET); //文件指针偏移到指定位置
			int i = 0;
			while (i * KEY_UNIT_SIZE < len) {
				if (sekeyindex % KEY_RATIO != 0 && (sekeyindex - 1) % KEY_RATIO != 0 && sekeyindex % 2 == (encrypt_flag ^ 0)) {
					fgets(pb, KEY_UNIT_SIZE + 1, fp);
						i++;
						pb += KEY_UNIT_SIZE;
				}
				else {
					fseek(fp, KEY_UNIT_SIZE, SEEK_CUR);
				}

				sekeyindex++;
			}
			//keyindex += len* KEY_UNIT_SIZE;
			rewind(fp);
		}
		else if (key_type == '1') {  //解密密钥
			fseek(fp, sdkeyindex * KEY_UNIT_SIZE, SEEK_SET); //文件指针偏移到指定位置
			int i = 0;
			while (i * KEY_UNIT_SIZE < len) {
				if (sdkeyindex % KEY_RATIO != 0 && (sdkeyindex - 1) % KEY_RATIO != 0 && sdkeyindex % 2 == (decrypt_flag ^ 1)) {
					fgets(pb, KEY_UNIT_SIZE + 1, fp);
					i++;
					pb += KEY_UNIT_SIZE;
				}
				else {
					fseek(fp, KEY_UNIT_SIZE, SEEK_CUR);
				}

				sdkeyindex++;
			}
			//keyindex += len* KEY_UNIT_SIZE;
			rewind(fp);
		}
		else { //sa密钥
			fseek(fp, keyindex * KEY_UNIT_SIZE, SEEK_SET); //文件指针偏移到指定位置
			int i = 0, plen = 0;
			while (i * KEY_UNIT_SIZE < len) {
				if (keyindex % KEY_RATIO == 0 || (keyindex - 1) % KEY_RATIO == 0) {
					int j = 0;
					for (int j = 0; j < KEY_UNIT_SIZE && plen < len; j++) {
						*pb = fgetc(fp);
						pb++;
					}

					i++;
					//pb += KEY_UNIT_SIZE;
				}
				else {
					fseek(fp, KEY_UNIT_SIZE, SEEK_CUR);
				}

				keyindex++;
			}
			//keyindex += len* KEY_UNIT_SIZE;
			rewind(fp);
		}

	}
	fclose(fp);
	pthread_rwlock_unlock(&keywr); //解锁
}

//派生密钥函数
void derive_key(const char *buf, const char* raw_key, const char* syn) {
	strcpy(buf, raw_key);
	strcat(buf, syn);
}
//sa密钥请求处理
void getk_handle(const char* spi, const char* keylen,int fd) {
	//判断是否已经同步，如果没有同步，首先进行双方同步
	if (!key_sync_flag) {
		bool ret=key_sync();
		if (!ret) {
			perror("key_sync error!\n");
			return;
		}
	}
	
	char buf[atoi(keylen)];
	//读取密钥
	readkey(buf, '2', keylen);
	send(fd, buf, len,0);
	key_sync_flag = false;

}
//会话密钥请求处理
void getsk_handle(const char* spi, const char* keylen, const char* syn, const char* key_type, int fd) {
	//如果双方没有同步加解密密钥池对应关系则首先进行同步
	if (!(encrypt_flag ^ decrypt_flag)) {
		bool ret=key_index_sync();
		if (!ret) {
			perror("key_index_sync error！\n");
			return;
		}
	}
	//判断syn是否为1，是则进行同步，否则不需要同步
	if (atoi(syn) == 1&& !key_sync_flag) {
		bool ret = key_sync();
		if (!ret) {
			perror("key_sync error!\n");
			return;
		}
	}
	static ekey_lw, ekey_rw, dkey_lw, dkey_rw;
	//记录首个数据包对应的量子密钥索引以及密钥窗口
	if (atoi(syn) == 1 && *key_type == '0') {
		
		ekey_sindex = sekeyindex;
		ekey_lw = atoi(syn);
		ekey_rw = atoi(syn) + cur_ekeyd;
	}
	if (atoi(syn) == 1 && *key_type == '1') {
		dkey_sindex = sdkeyindex;
		dkey_lw= atoi(syn);
		dkey_rw= atoi(syn)+ cur_ekeyd;
	}
	
	char buf[BUFFLEN], * pb = buf;
	//读取密钥
	if (*key_type == '0') {  //加密密钥
		if (atoi(syn) ==1 || atoi(syn) >= ekey_rw) {  //如果还没有初始的密钥或者超出密钥服务范围需要更新原始密钥以及syn窗口,协商新的密钥派生参数
			readkey(raw_ekey, key_type, keylen);
			//密钥派生参数协商
			//更新窗口
			ekey_lw = ekey_rw;
			ekey_rw = ekey_rw + cur_ekeyd;
		}
		derive_key(buf, raw_ekey, syn);
	}
	else {  //解密密钥
		if (atoi(syn) == 1 || atoi(syn) >= dkey_rw) {  //如果还没有初始的密钥或者超出密钥服务范围需要更新原始密钥以及syn窗口,协商新的密钥派生参数
			readkey(raw_dkey, key_type, keylen);
			//密钥派生参数协商
			//更新窗口
			dkey_lw = dkey_rw;
			dkey_rw = dkey_rw + cur_ekeyd;
		}
		derive_key(buf, raw_dkey, syn);
	}
	printf("%s\n", buf);
	send(fd, buf, strlen(buf), 0);
}
void keysync_handle(const char* tdelkeyindex, const char* tkeyindex, const char* tsekeyindex, const char* tsdkeyindex, int fd) {

	char buf[BUFFLEN];
	sprintf(buf, "keysync %d %d %d %d", delkeyindex, keyindex, sekeyindex, sdkeyindex);
	send(fd, buf, BUFFLEN, 0);
	delkeyindex = max(tdelkeyindex, delkeyindex);
	keyindex = max(tkeyindex, keyindex);
	sekeyindex = max(tsekeyindex, sekeyindex);
	sdkeyindex = max(tsdkeyindex, sdkeyindex);
	key_sync_flag = true;
	skey_sync_flag = true;

}
void kisync_handle(const char* encrypt_i, const char* decrypt_i, int fd) {
	encrypt_flag = atoi(decrypt_i);
	decrypt_flag = atoi(encrypt_i);
	char buf[BUFFLEN];
	sprintf(buf, "kisync %d %d", encrypt_flag, decrypt_flag);
	send(fd, buf, strlen(buf), 0);

}

void desync_handle(const char* key_d, int fd) {
	int tmp_keyd = atoi(key_d);
	next_dkeyd = tmp_keyd;
	char buf[BUFFLEN];
	sprintf(buf, "desync %d", next_dkeyd);
	send(fd, buf, strlen(buf), 0);
}
void do_recdata(int fd,int epfd) {
	char buf[BUFFLEN],path[BUFFLEN];
	int n = get_line(fd, buf, BUFFLEN);
	if (n < 0) {
		perror("getline error\n");
		exit(1);
	}   
	else if (n == 0) {
		printf("client closed...\n");
		discon(fd, epfd);
	}
	else {
		
		//memcpy(path, buf + l + 1, s - l - 1);
		char method[16], path[256], protocol[16], arg1[32], arg2[32], arg3[32],arg4[32];
		int key_type;
		sscanf(buf, "%[^ ] %[^ ] %[^ ] %[^ ] %[^ ]", method, arg1, arg2, arg3, arg4);
		//对应于getk   arg1==spi, arg2=keylen(字节)
		//对应于getsk  arg1==spi, arg2=keylen(字节), arg3=syn,arg4=keytype
		//对应于keysync  arg1==delkeyindex, arg2=keyindex, arg3=sekeyindex,arg4=sdkeyindex
		//对应于key_index_sync arg1==encrypt_index, arg2==decrypt_index
		//对应于derive_sync  arg1==key_d
		printf("%s %s %s %s %s\n", method, arg1, arg2, arg3, arg4);
		while (1)
		{
			n= get_line(fd, buf, BUFFLEN);
			if (n == 0) {
				discon(fd, epfd);
			}
			if (n == '\n') {
				break;
			}
			else if(n==-1)
			{
				break;
			}
		}
		if (strncasecmp(method, "getk",4) == 0) {
			//char* p = path + 1;
			getk_handle(arg1, arg2,fd);
			discon(fd, epfd);
		}
		else if (strncasecmp(method, "getsk", 5) == 0) {
			getsk_handle(arg1, arg2, arg3, arg4, fd);
			discon(fd, epfd);
		}
		else if (strncasecmp(method, "keysync", 7) == 0) {
			keysync_handle(arg1, arg2, arg3, arg4, fd);
			discon(fd, epfd);
		}
		else if (strncasecmp(method, "kisync", 7) == 0) {
			kisync_handle(arg1, arg2, fd);
			discon(fd, epfd);
		}
		else if (strncasecmp(method, "desync", 6) == 0) {
			desync_handle(arg1, fd);
			discon(fd, epfd);
		}
		
	}
	

}
int init_listen(int port, int epfd) {
	int lfd,ret;
	struct epoll_event tep;
	struct sockaddr_in serv_addr;
	socklen_t client_addr_size;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	inet_pton(AF_INET, "0.0.0.0", &serv_addr.sin_addr.s_addr);
	lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0) {
		perror("socket create error!\n");
		exit(1);
	}
	//端口复用
	int opt = 1;
	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	
	int br = bind(lfd, (struct sockaddr_in*)&serv_addr, sizeof(serv_addr));
	if (br < 0) {
		perror("bind error!\n");
		exit(1);
	}
	//listen上限
	listen(lfd, 128);
	//添加监听事件上树
	tep.events = EPOLLIN;
	tep.data.fd = lfd;
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, lfd, &tep);
	if (ret == -1) {
		perror("epoll_ctl_add error!\n");
		exit(1);
	}
	return lfd;
}
void epoll_run(int port) {
	int epfd,lfd,ret,i;
	struct epoll_event ep[MAXS];
	epfd = epoll_create(MAXS);
	lfd = init_listen(port, epfd);

	while (1) {
		ret = epoll_wait(epfd, ep, MAXS, -1);

		if (ret < 0) {
			perror("epoll_wait error!\n");
			exit(1);
		}
		for (i = 0; i < ret; i++) {
			if (ep[i].events & EPOLLIN && ep[i].data.fd == lfd) {
				do_crecon(lfd, epfd);  //新建连接事件
			}
			else if (ep[i].events & EPOLLIN) {
				do_recdata(ep[i].data.fd,epfd); //密钥请求及同步事件
			}
			else {
				continue;
			}
		}
	}

}
//字符转换
char transform(int i) {
	if (i < 10) {
		return i + '0';
	}
	else if (i == 10) {
		return 'a';
	}
	else if (i == 11) {
		return 'b';
	}
	else if (i == 12) {
		return 'c';
	}
	else if (i == 13) {
		return 'd';
	}
	else if (i == 14) {
		return 'e';
	}
	else{
		return 'f';
	}
}
//密钥写入线程
void* thread_write() {
	//首先定义文件指针：fp
	FILE* fp;
	remove(KEY_FILE);
	printf("key supply starting...\n");
	//模拟不断写入密钥到密钥池文件
	while (1) {
		char buf[KEY_CREATE_RATE];
		int i = 0;
		srand((unsigned int)time(NULL));
		for (; i < KEY_CREATE_RATE; i++) { //随机形成密钥串
			//srand((unsigned int)time(NULL));
			int ret = i % 16;
			buf[i] = transform(ret);
		}
		
		pthread_rwlock_wrlock(&keywr); //上锁
		fp= fopen(KEY_FILE, "a+");
		fseek(fp, 0, SEEK_END); //定位到文件末 
		int nFileLen = ftell(fp); //文件长度
		fseek(fp, 0, SEEK_SET); //恢复到文件头
		//判断文件大小，若文件大于设定的值则不再写入
		if (nFileLen < MAX_KEYFILE_SIZE) {
			fputs(buf, fp);
			//printf("%s\n", buf);
		}
		fclose(fp);
		pthread_rwlock_unlock(&keywr); //解锁
		
		sleep(1); //等待1s
	}
	
	pthread_exit(0);
}
int main(int argc, char* argv[]) {

	key_sync_flag = false, skey_sync_flag = false; //密钥同步标志设置为false
	delkeyindex=0, keyindex=0, sekeyindex=0, sdkeyindex=0;  //初始化密钥偏移
	pthread_rwlock_init(&keywr, NULL); //初始化读写锁
	encrypt_flag=0,decrypt_flag=0; //初始化加解密密钥池对应关系
	cur_ekeyd = INIT_KEYD;  //初始化密钥派生参数
	cur_dkeyd = INIT_KEYD;  //初始化密钥派生参数
	//raw_ekey = NULL, prived_ekey = NULL;  //初始化加密密钥
	
	int fd, ar, ret,count=0,n,i,epfd;
	struct epoll_event tep,ep[MAXS];
	pthread_t tid, pid;
	char buf[1024],client_ip[1024]; 
	if (argc < 2) {
		//默认服务器监听端口
		SERV_PORT = DF_SERV_PORT;
	}
	else {
		SERV_PORT = atoi(argv[1]);
	}
	
	pthread_create(&tid, NULL, thread_write, NULL);  //密钥写入线程启动
	pthread_detach(tid); //线程分离
	
	epoll_run(SERV_PORT); //启动监听服务器，开始监听密钥请求
	
	pthread_rwlock_destroy(&keywr); //销毁读写锁
	return 0;
}