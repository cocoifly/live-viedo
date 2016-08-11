///////////////////////////////////////////////////////////
//  PublicPlaceImplementation.cpp
//  Implementation of the Class PublicPlaceImplementation
//  Created on:      22-十一月-2010 15:32:34
//  Original author: wangyw
///////////////////////////////////////////////////////////

#ifdef _WIN32
# define WIN32_LEAN_AND_MEAN
#endif

#include <Ice/Ice.h>  // include _WIN32_WINNT
#include "email/ui_mail_parse.h"
#include "public_place_implementation.h"
#include "log/log_base_info.h"
#include "communication/danal_center_com.h"
#include "communication/wmc_commu_extend.h"
#include "utils/database.h"
#include "define_protocol_type.h"
#include "zbl/zbl.h"
#include "httpplug/ui_http_vid.h"
#include "httpplug/http_roller_parse.h"
#include "utils/ztime.h"
#include "utils/ui_debug.h"
#include "utils/ui_util.h"
#include "utils/ui_util_url_decode.h"
#include "utils/charactor.h"
#include "store/store_data.h"
#include "unit_config/unit_config.h"
#include "log_analy/cookie_list.h"
#include "../httpplug/roller/inc/ui_search_engine.h"
#include "wmc_sync/wmc_sync.h"

#ifdef _WIN32
#include <direct.h>
#include <io.h>
#define DIR_CHAR "\\"
#else
#define DIR_CHAR "/"
#endif

void GetTime(char * buf);
void GetTime4Wmc(char *buf);

PublicPlace *CreatePublicPlace(const string &UnitCode)
{
	PublicPlaceImplementation *pret=new PublicPlaceImplementation(UnitCode);
	if(pret ==NULL){
		return NULL;
	}
	pret->UnitCode=UnitCode;
	return pret;
}

PublicPlaceImplementation::PublicPlaceImplementation(const string &UnitCode)
{
	myPolicy=NULL;
	realname=NULL;
	onlineuser=NULL;
	this->UnitCode = UnitCode;
	realname=createRealName(this->UnitCode);
	onlineuser=createOnlineUser(this->UnitCode);
	
	mhttpValue=createHttpValue();
	mhttpEmail=createEmail();
	mhttpCookie = createHttpCookie(); //cookie

	//myPolicy = CreateAlarmPolicy();

	RecycleThread *rt=RecycleThread::getInstance();
	rt->AddLogBuffer(mhttpValue);
	rt->AddLogBuffer(mhttpEmail);
	rt->AddLogBuffer(mhttpCookie);//cookie

	mApBuffer = NULL;
	mStaBuffer = NULL;
	mInit = 0;

	mDisposeVidNum = GetVidNum();
}



PublicPlaceImplementation::~PublicPlaceImplementation()
{

}

void PublicPlaceImplementation::AnalyLog(void *log,int type)
{
	if(NULL == log){
		return ;
	}
	
	switch((FkeLogType_t)type){
		case FLOG_HTTP_ACCESS:
		DebugLog::Log(5, "AccessLogDeal\n");
			AccessLogDeal(log);
			break;
		case FLOG_HTTP_VALUE:
		DebugLog::Log(5, "HttpValueDeal\n");
			HttpValueDeal(log);
			break;
		case FLOG_VID:
		DebugLog::Log(5, "VirtualIDDeal\n");
			VirtualIDDeal(log);
			break;
		case FLOG_FLOWS:
		DebugLog::Log(5, "FlowDeal\n");
			FlowDeal(log);
			break;
		case FLOG_OTHER_ACCESS:
		DebugLog::Log(5, "FLOG_OTHER_ACCESS:\n");
			SimpAccessDeal(log);
			break;
		case FLOG_FRIENDVID:
		DebugLog::Log(5, "VirtualFriendDeal\n");
			VirtualFriendDeal(log);
			break;
		case FLOG_GROUPMSG:
		DebugLog::Log(5, "GroupChatDeal\n");
			GroupChatDeal(log);
			break;
		case FLOG_IMMSG:
		DebugLog::Log(5, "ChatDeal\n");
			this->ChatDeal(log);
			break;
		case FLOG_MAILDATA:
		DebugLog::Log(5, "EmailDeal\n");
			EmailDeal(log);
			break;
		//case FLOG_SEARCH_KEYWORD:
		//DebugLog::Log(5, "88888888888888KeywordDeal\n");
		//	KeywordDeal(log);//由于关键词在后端处理。此处不处理 ???? what ????
		//	break;
		case FLOG_TELNO:
		DebugLog::Log(5, "VidTelNoDeal\n");
			VidTelNoDeal(log);
			break;
		case FLOG_REGIST_REALNAME:
		DebugLog::Log(5, "RealnameDeal\n");
			RealnameDeal(log);
			break;
		case FLOG_UNREGIST_REALNAME:
		DebugLog::Log(5, "RealnameOffDeal\n");
			this->RealnameOffDeal(log);
			break;
		case FLOG_SYN_REALNAME:
		DebugLog::Log(5, "SynRealname\n");
			this->SynRealname(log);
			break;
		case FLOG_ONLINEUSER:
		DebugLog::Log(5, "OnlineUserDeal\n");
			OnlineUserDeal(log);
			break;
		case FLOG_OFFLINEUSER:
		DebugLog::Log(5, "OnlineUserOffDeal\n");
			this->OnlineUserOffDeal(log);
			break;
		case FLOG_SYN_ONLINEUSER:
		DebugLog::Log(5, "SynOnlineUser\n");
			SynOnlineUser(log);
			break;
        case FLOG_PURE_VID_INFO:
		DebugLog::Log(5, "PureVidDeal\n");
            PureVidDeal(log);
            break;
		case FLOG_HTTP_COOKIE:
		DebugLog::Log(5, "HttpCookieDeal\n");
			HttpCookieDeal(log);
			break;
        case FLOG_MAC_ENTITY_SYN_STA:
		DebugLog::Log(5, "TotalSynSta\n");
            this->TotalSynSta(log);
            break;
        case FLOG_MAC_ENTITY_SYN_AP:
		DebugLog::Log(5, "TotalSynAp\n");
            this->TotalSynAp(log);
            break;
        case FLOG_MAC_ENTITY_DELTA_STA:
		DebugLog::Log(5, "DeltaSynSta\n");
            this->DeltaSynSta(log);
            break;
        case FLOG_MAC_ENTITY_DELTA_AP:
		DebugLog::Log(5, "DeltaSynAp\n");
            this->DeltaSynAp(log);
            break;
		default:
			
			return;
	}
}


void PublicPlaceImplementation::SetPolicy(AlarmPolicy *pAlarmPolicy) 
{
	myPolicy=pAlarmPolicy;
}

void PublicPlaceImplementation::GetStatus(int &onlinenum,int &vidnum)
{
	onlinenum=this->onlineuser->GetUserNum();
	vidnum=mDisposeVidNum;
}

int PublicPlaceImplementation::GetOnlineUserSet(vector<NbPsmOnlineUserInfo> &myset)
{
	return this->onlineuser->GetOnlineUserSet(myset);
}

void PublicPlaceImplementation::RealnameDeal(void *log)
{
	NbPsmRealNameInfo *pRealname=(NbPsmRealNameInfo*)log;
	string RealnameId = pRealname->Uid;
	if(realname!=NULL && NULL != realname->GetRealName(RealnameId)){	// 已存在则return
		return;
	}
	
	pRealname->RegistTime = time(NULL);
	pRealname->UnregistTime = 0;
	// 旅业接口可能传的房间号是utf8的中文，在这里做一下转换兼容
	CorrectRoomNum(pRealname->RoomNum, sizeof(pRealname->RoomNum));
	
	if((pRealname->AuthType & IP_AUTH_TYPE) == 0){	// 不是ip认证
		memset(pRealname->Ip, 0, sizeof(pRealname->Ip));
	}
	if((pRealname->AuthType & MAC_AUTH_TYPE) == 0){		// 不是mac认证
		memset(pRealname->Mac, 0, sizeof(pRealname->Mac));
	}
	
	// 1.实名存储
	realname->AddRealName(*pRealname,UnitCode);

	// 2.实名报警
	myPolicy->lock.Lock();
	myPolicy->Apply(*pRealname, UnitCode);
	myPolicy->lock.UnLock();

	// 3.传给管理中心
	DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();
	dcc->PostRegist(UnitCode,pRealname,NULL);

/* psm5.7.2改由dacoll将数据存入数据库，将以下部分注释. by liujl
#ifndef X86
	// 将实名存入数据库中, add by liujl
	static StoreData *sd = StoreData::GetInstance();
	sd->RealNameSave(*pRealname);
#endif
*/
}

void PublicPlaceImplementation::RealnameOffDeal(void *log)
{
	NbPsmRealNameInfo *pRealname=(NbPsmRealNameInfo*)log;
	pRealname->RegistTime=0;
	// 旅业接口可能传的房间号是utf8的中文，在这里做一下转换兼容
	CorrectRoomNum(pRealname->RoomNum, sizeof(pRealname->RoomNum));	
	
	const NbPsmRealNameInfo *pregiset=realname->GetRealName(pRealname->Uid);
	if(pregiset ==NULL){
		DebugLog::Log(3, "退房记录中找不到对应的入住信息，现补充入住信息\n");
		RealnameDeal(log);
	}else{	// 补充上线时间
		pRealname->RegistTime = pregiset->RegistTime;
	}
	pRealname->UnregistTime=time(NULL);

	// 实名报警
	myPolicy->lock.Lock();
	myPolicy->Apply(*pRealname, UnitCode);
	myPolicy->lock.UnLock();

	//  删除顾客实名
	realname->DeleteRealName(UnitCode,pRealname);	
	//  发送到管理中心
	DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();
	dcc->PostUnregist(UnitCode,pRealname,NULL);

/* psm5.7.2改由dacoll将数据存入数据库，将以下部分注释. by liujl
#ifndef X86
	// 将实名存入数据库中, add by liujl
	static StoreData *sd = StoreData::GetInstance();
	sd->RealNameSave(*pRealname);
#endif
*/
}

void PublicPlaceImplementation::SynRealname(void *log)
{
	RNListT *RealList=(RNListT*)log;
	RNListT NeedAddList, NeedDelList;	// 需添加的链表, 需删除的链表
	RNListT::iterator AddIt, DelIt;
	NeedAddList.clear();
	NeedDelList.clear();
	realname->CmpRealName(*RealList, NeedAddList, NeedDelList);
	DebugLog::Log(3, "对比场所端与业务后台的实名, 杼砑覽%d]个, 需删除[%d]个\n", 
		(int) NeedAddList.size(), (int) NeedDelList.size());

	// 添加缺少的实名
	for(AddIt = NeedAddList.begin(); AddIt != NeedAddList.end(); AddIt++){
		RealnameDeal(&(*AddIt));
	}

	// 删除需要删除的实名
	for(DelIt = NeedDelList.begin(); DelIt != NeedDelList.end(); DelIt++){
		RealnameOffDeal(&(*DelIt));
	}
}

void PublicPlaceImplementation::OnlineUserDeal(void *log)
{
	NbPsmOnlineUserInfo *pOnlineUser=(NbPsmOnlineUserInfo *)log;
	pOnlineUser->OnlineTime = time(NULL);
	pOnlineUser->LastActiveTime=time(NULL);
	pOnlineUser->OfflineTime=0;
	pOnlineUser->Nsinfo.MailSend=0;
	string RealNameId = pOnlineUser->Rlinfo.Uid;
	
	// 旅业接口可能传的房间号是utf8的中文，在这里做一下转换兼容
	CorrectRoomNum(pOnlineUser->Rlinfo.RoomNum, sizeof(pOnlineUser->Rlinfo.RoomNum));

	const NbPsmRealNameInfo *pRealname = realname->GetRealName(RealNameId);
	if(NULL == pRealname){
        DebugLog::Log(5, "onlineuserdeal pPrealname is null.\n");
		//  补实名
		DebugLog::Log(3, "上线记录中找不到对应的实名，现补充实名\n");
		NbPsmRealNameInfo Realname = pOnlineUser->Rlinfo;
		RealnameDeal(&Realname);		//  这里必须使用临时变量作为参数传入RealnameDeal
		pOnlineUser->Rlinfo.RegistTime = Realname.RegistTime;
	}else{
        DebugLog::Log(5, "onlineuserdeal pPrealname is not null.\n");
		pOnlineUser->Rlinfo.RegistTime = pRealname->RegistTime;
	}

	//  顾客记录存储
	if(onlineuser!=NULL){
		onlineuser->AddOnlineUser(*pOnlineUser,UnitCode);
	}

	// 传给管理中心
	DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();
	dcc->PostOnlineUser(UnitCode,&pOnlineUser->Rlinfo,pOnlineUser);

	// 关联虚拟身份记录
	OnlineVid(UnitCode.c_str(),pOnlineUser->Rlinfo.Ip);

	// 传给无线管控中心
	WmcSync::GetInstance()->OnlineSync(UnitCode, pOnlineUser);

    //2015/10/19 --shixk
	pRealname = realname->GetRealName(RealNameId);
	if(NULL == pRealname)
        DebugLog::Log(5, "onlineuserdeal pPrealname 2 is null.\n");
    else
        DebugLog::Log(5, "onlineuserdeal pPrealname 2 is not null.\n");
    Psm2WmcCommu::GetInstance()->PostCustomOnlineLog(UnitCode, pRealname, pOnlineUser);
    //--shixk

/* psm5.7.2改由dacoll将数据存入数据库，将以下部分注释. by liujl
	// 将在线顾客记录存入数据库中
	static StoreData *sd = StoreData::GetInstance();
	sd->OnlineUserSave(*pOnlineUser);
*/

}

void PublicPlaceImplementation::OnlineUserOffDeal(void *log)
{
	NbPsmOnlineUserInfo *pOnlineUser=(NbPsmOnlineUserInfo *)log;
	pOnlineUser->OnlineTime=0;
	pOnlineUser->LastActiveTime=time(NULL);
	const NbPsmOnlineUserInfo *ponline=NULL;
	string RealnameId = pOnlineUser->Rlinfo.Uid;
	
	//  旅业接口可能传的房间号是utf8的中文，在这里做一下转换兼容
	CorrectRoomNum(pOnlineUser->Rlinfo.RoomNum, sizeof(pOnlineUser->Rlinfo.RoomNum));

	if(onlineuser!=NULL){
		ponline=onlineuser->GetOnlineUserByID(pOnlineUser->UserId);
	}
	if(ponline==NULL){
		//  补充上线记录
		DebugLog::Log(3, "下线记录中找不到对应的上线记录，现补充上线记录\n");
		OnlineUserDeal(log);
	}else{
		pOnlineUser->Rlinfo.RegistTime = ponline->Rlinfo.RegistTime;
		pOnlineUser->OnlineTime = ponline->OnlineTime;
	}
	// 在补充上线记录时，会将OfflineTime设为0，所以OfflineTime要在补充上线记录后设置
	pOnlineUser->OfflineTime = time(NULL);

	// 虚拟身份下线处理
	OffLine(UnitCode.c_str(),pOnlineUser->Rlinfo.Ip);

	// 传给管理中心
	DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();
	dcc->PostOfflineUser(UnitCode,&pOnlineUser->Rlinfo,pOnlineUser);

    //2015/10/19 --shixk
	const NbPsmRealNameInfo *pRealname = realname->GetRealName(pOnlineUser->Rlinfo.Uid);
    Psm2WmcCommu::GetInstance()->PostCustomOfflineLog(UnitCode, pRealname, pOnlineUser);
    //--shixk
	
	// 删除顾客记录
	onlineuser->DeleteUser(UnitCode,pOnlineUser);

/*   psm5.7.2改由dacoll将数据存入数据库，将以下部分注释. by liujl
	// 将在线顾客记录存入数据库中
	static StoreData *sd = StoreData::GetInstance();
	sd->OnlineUserSave(*pOnlineUser);
*/
}

void PublicPlaceImplementation::SynOnlineUser(void *log)
{
	OUListT *OuList = (OUListT *) log;
	list<struct NbPsmOnlineUserInfo> NeedAddList;		//  需要添加的在线顾客记录
	list<struct NbPsmOnlineUserInfo> NeedDelList;		//  需要删除的在线顾客记录
	list<struct NbPsmOnlineUserInfo>::iterator AddIt, DelIt;
	onlineuser->CmpOnlineUser(*OuList, NeedAddList, NeedDelList);
	DebugLog::Log(3, "对比场所端与业务后台的在线顾客记录, 需添加[%d]个, 需删除[%d]个\n", 
		(int) NeedAddList.size(), (int) NeedDelList.size());

	//  添加缺少的在线顾客记录
	for(AddIt = NeedAddList.begin(); AddIt != NeedAddList.end(); AddIt++){
		OnlineUserDeal(&(*AddIt));
	}

	//  删除多余的在线顾客记录
	for(DelIt = NeedDelList.begin(); DelIt != NeedDelList.end(); DelIt++){
		OnlineUserOffDeal(&(*DelIt));
	}
}

void PublicPlaceImplementation::VirtualFriendDeal(void *log)
{
	FriendVidLog *vlog=(FriendVidLog *)log;

	char strtime[64] = {0};
	time_t current = time(NULL);
	vlog->Time = z_time_t2str(strtime, &current, ZTIMESTR_TYPE1);
	
	//关联在线用户记录
	const NbPsmOnlineUserInfo *ponline=onlineuser->GetOnlineUser(vlog->Host,UnitCode);
	const NbPsmRealNameInfo * preal = NULL;
	if(ponline !=NULL){
		//关联实名
		preal=realname->GetRealName(ponline->UserId);

		//报警
		myPolicy->lock.Lock();
		this->myPolicy->Apply(*vlog,FLOG_FRIENDVID,preal,ponline,UnitCode);
        myPolicy->lock.UnLock();


        DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();
        dcc->PostVidFriendLog(*vlog,UnitCode,preal,ponline);
        //2015/10/19 --shixk
        if(preal != NULL)
        {
            DebugLog::Log(5, "VirtualFriendDeal PostFriendLog will be invoked, preal != NULL.\n");
            Psm2WmcCommu::GetInstance()->PostFriendLog(UnitCode, preal, ponline, vlog);
            //--shixk
        }
        else
        {
            DebugLog::Log(5, "VirtualFriendDeal PostFriendLog won't be invoked, preal == NULL.\n");
            preal=realname->GetRealName(ponline->Rlinfo.Uid);
            if(preal != NULL)
                Psm2WmcCommu::GetInstance()->PostFriendLog(UnitCode, preal, ponline, vlog);
        }
    }else{
        //报警
        myPolicy->lock.Lock();
        this->myPolicy->Apply(*vlog,FLOG_FRIENDVID,NULL,ponline,UnitCode);
		myPolicy->lock.UnLock();

		DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();
		dcc->PostVidFriendLog(*vlog,UnitCode,NULL,ponline);
	}

}

void PublicPlaceImplementation::AccessLogDeal(void *log)
{
    DebugLog::Log(5, "AccessLogDeal\n");
    HttpAccessLog *vlog=(HttpAccessLog *)log;
	char strtime[64] = {0};
	string UserId = "";
	time_t current = time(NULL);
	vlog->Time = z_time_t2str(strtime, &current, ZTIMESTR_TYPE1);
	NbfkeUtil::GetGuid(vlog->LogID);

	//关联在线用户记录
	const NbPsmOnlineUserInfo *ponline=onlineuser->GetOnlineUser(vlog->Host,UnitCode);

	const NbPsmRealNameInfo * preal = NULL;
	if(ponline !=NULL){
		//关联实名
		preal=realname->GetRealName(ponline->Rlinfo.Uid);

		//报警
		myPolicy->lock.Lock();
		this->myPolicy->Apply(*vlog,FLOG_HTTP_ACCESS,preal,ponline,UnitCode);
		myPolicy->lock.UnLock();

		UserId = ponline->UserId;
        //2015/10/18 --shixk
        if(preal != NULL)
        {
            Psm2WmcCommu::GetInstance()->PostAccessRecordLog(UnitCode, preal, ponline, vlog);
            //Psm2WmcCommu::GetInstance()->PostInternetAccessLog(UnitCode, preal, ponline);
        }
        //--shixk
	}else{
		//报警
		myPolicy->lock.Lock();
		this->myPolicy->Apply(*vlog,FLOG_HTTP_ACCESS,NULL,ponline,UnitCode);
		myPolicy->lock.UnLock();
		preal = NULL;
	}
	UnitConfig *config = UnitConfig::GetInstance();
	int IsConcenter = config->GetIsConcenter();
	if(0 == IsConcenter){	 // 非集中式，上传访问记录
		//上传
		DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();
		dcc->PostHttpAccess(*vlog,UnitCode,preal,ponline);
	}
		
	StoreData *sd = StoreData::GetInstance();
	sd->LogSave(*vlog, UserId);
	
}

void PublicPlaceImplementation::HttpValueDeal(void *log)
{
	HttpValueLog *vlog=(HttpValueLog *)log;

	char strtime[64] = {0};
	time_t current = time(NULL);
	vlog->Time = z_time_t2str(strtime, &current, ZTIMESTR_TYPE1);

	/*if(vlog->TotalLen != vlog->Content.size()){
		return;
	}*/////
	if( vlog->TotalLen > 10*1024*1024){
		return;
	}

	if(mhttpValue->LogInbufer(vlog) == 0){			//  没有组合成完整的http vlaue数据，则返回
		return;
	}
	
	vlog=(HttpValueLog*)mhttpValue->GetBufer();

    // URL解码
	static CodingDecode cdobj;
	const char *str = NULL;
	char *strdecode = cdobj.UrlDecode(vlog->Content.c_str(),(unsigned int)vlog->Content.size());
	if(!strdecode){
		str = vlog->Content.c_str();
	}else{
		str = strdecode;
	}
    
    // HTTPValue 报警, 只针对POST, 为了赌博网站
    if(vlog->Action==2){     //1:GET,2:POST
        const NbPsmOnlineUserInfo *ponline = onlineuser->GetOnlineUser(vlog->Host, UnitCode);
        const NbPsmRealNameInfo *preal = NULL;
        if(ponline!=NULL){
            preal = realname->GetRealName(ponline->Rlinfo.Uid);
        }
        myPolicy->lock.Lock();
        myPolicy->Apply(*vlog, FLOG_HTTP_VALUE, preal, ponline, UnitCode);
        myPolicy->lock.UnLock();
        //2015/10/18 --shixk
        if(preal == NULL)
            DebugLog::Log(5, "HttpValueDeal: preal == NULL, PostPostLog won't be invoked\n");
        else
        {
            DebugLog::Log(5, "HttpValueDeal: preal != NULL, PostPostLog will be invoked.\n");
            Psm2WmcCommu::GetInstance()->PostPostLog(UnitCode, preal, ponline, vlog);  //ServiceType Appprotocol Apptype FIXME
        }
        //--shixk
    }
    
    if(vlog->Action == 1){//处理关键词只针对get
         DebugLog::Log(5, "DisposeKeyword: only for get.\n");
		 DisposeKeyword(vlog);	
    }
    
	// 取虚拟身份
	int ret = 0;
	HttpVid vid;
	HttpVidGet *hvgobj = HttpVidGet::Getinstance();
	if(hvgobj == NULL){
		return;
	}
	/*
	if(strdecode){
		cdobj.CodeValueFree(strdecode);
	}
	return ;
	*/
	// 处理VID的URL时，忽略'?'后面的部分
	// 虽然GetVid的参数有指定url的长度，但内部实现不安全，有忽略长度直接将整个char*看作url的情况!
	string real_host;
    size_t url_size = vlog->Url.find_first_of("?");
	if(url_size == string::npos){
        real_host = vlog->Url;
    }else{
        real_host.assign(vlog->Url.c_str(), url_size);
    }
	
	//修正对get请求的正确处理方式
	if(vlog->Action == 0 || vlog->Action == 1){
		ret = hvgobj->GetVid(real_host.c_str(),(unsigned int)real_host.size(),str,(unsigned int)strlen(str),NULL,0,&vid);
	}else{
		ret = hvgobj->GetVid(real_host.c_str(),(unsigned int)real_host.size(),NULL,0,str,(unsigned int)strlen(str),&vid);
	}

	//临时增加处理手机信息
	DisposePhoneInfo(vlog,real_host,str,(unsigned int)strlen(str),vlog->Action);
	//临时增加处理网易android博客
	DisposeWangyiBlog(vlog,real_host,str,(unsigned int)strlen(str),vlog->Action);

	if(ret >= 0){
		// 虚拟身份业务
		VidLog vidlog;
		vidlog.AppProtocol = vid.type;
		vidlog.Host = vlog->Host;
		vidlog.LogID = vlog->LogID;
		vidlog.ServiceType = vlog->ServiceType;
		vidlog.Time = vlog->Time;
		vidlog.Account = vid.account;
		vidlog.Domain = vlog->Domain;
		vidlog.Nickname = "";
		vidlog.Password = vid.password;
		vidlog.Url = real_host;
		vidlog.Action = 0 ;

        ConvertCode(LCCT_UTF8, vidlog.Account);

		DebugLog::Log(3, "发现web虚拟身份 VidLog: UnitCode[%s], Account[%s], Action[%d], Domain[%s], Nickname[%s], Password[%s], Url[%s], "
		"AppProtocol[%d], Host[%s], LogID[%s], ServiceType[%d], Time[%s]\n",
		UnitCode.c_str(), vidlog.Account.c_str(), vidlog.Action, vidlog.Domain.c_str(), vidlog.Nickname.c_str(), vidlog.Password.c_str(), vidlog.Url.c_str(),
		vidlog.AppProtocol, vidlog.Host.c_str(), vidlog.LogID.c_str(), vidlog.ServiceType, vidlog.Time.c_str()
		);
		// 调用虚拟身份处理逻辑
		VirtualIDDeal((void *)&vidlog);
		if(strdecode){
			cdobj.CodeValueFree(strdecode);
		}
        
		return ;
	}


	//BBS , WebMail 还原
	HTTPPostApplicationParse *hpapobj = HTTPPostApplicationParse::GetSingleton();
	HttpPostBaseInfo hpbi;
	hpbi.mUnitCode = UnitCode;
	hpbi.mNetLogBase = *((NetLogBaseInfo *)vlog);
	hpbi.mPostUrl = vlog->Url;
	hpbi.mDomain = vlog->Domain;
	hpbi.mRefer = vlog->Refer;
	hpbi.mAction = vlog->Action;
	hpbi.BBSHandle = BBSRollerLogDispose;
	hpbi.WebMailHandle = WebMailRollerLogDispose;
	hpbi.WeiboHandle = WeiboRollerDispose;
    hpbi.WebMailAttHandle = WebMailAttRollerDispose;
	hpbi.CookieHandle = GetCookieLog;
	hpbi.mUserHandle = this;
	DebugLog::Log(5,"bbs还原,refer = %s\n",vlog->Refer.c_str()); 
	hpapobj->Parse(hpbi,vlog->Domain.c_str(), vlog->Content.c_str(), vlog->Content.size(), vlog->Url.c_str(),vlog->Refer.c_str());

	if(strdecode){
		cdobj.CodeValueFree(strdecode);
	}
	
}


/*
samuel 2014-09-24
disposed android wangyi blog,just for test...wtf!
url:
actionContent:
contentlen:
action: 0=get 1=post
return:NULL
*/

void PublicPlaceImplementation::DisposeWangyiBlog(const HttpValueLog* vlog,const string& url, const char* content,unsigned int contentlen,int action)
{
	if(content == NULL || contentlen == 0) return;

	if(vlog->Domain.compare("wap.blog.163.com") != 0) return;

	if(url.find("/w2/dwr/call/plaincall/MobileBlogBean") == string::npos) return;

	BbsRoller roller;
	//确定是发帖还是回复
	if(strstr(content,"addBlogComment") != NULL){
		//回复
		roller.Action = 1;
	}else if(strstr(content,"addBlog") != NULL){
		//发帖
		roller.Action = 0;
	}else{
		//全部不符合
		return;
	}

	if(roller.Action == 1){
		//回复，只有内容，没有标题
		ClipFlag(content,contentlen,"c0-param0=string:","\n",roller.content);
		ConvertCode(LCCT_UTF8, roller.content);
	}else{
		//发帖，有标题和内容
		ClipFlag(content,contentlen,"c0-param0=string:","\n",roller.title);
		ClipFlag(content,contentlen,"c0-param0=string:","\n",roller.content);
		ConvertCode(LCCT_UTF8, roller.title);
		ConvertCode(LCCT_UTF8, roller.content);
	}

	string strvid;
	ClipFlag(vlog->Url.c_str(),vlog->Url.length(),"h=","&",strvid);

	//构造内容还原日志

	roller.bar_name = "网易博客";
	roller.AppProtocol = 20013;
	roller.ServiceType = SERVICE_TYPE_BLOG;
	roller.Posturl = url;             //url
	roller.LinkUrl = vlog->Url;		 //url类别,遵循url名单库的分类规则,例如大类是3,小类是2,则url_type=31.默认-1,表示无分类
	roller.proto = 3100011;           		//暂时使用网易论坛协议号 liucy
	roller.subtitle = "";		//子标题	
	roller.domain = vlog->Host;			
	time_t current = time(NULL);
	char strtime[32] = {0};
	roller.Time = z_time_t2str(strtime, &current, ZTIMESTR_TYPE1);

	//关联在线用户记录
	const NbPsmOnlineUserInfo *ponline=onlineuser->GetOnlineUser(vlog->Host,UnitCode);

	if(ponline !=NULL){
		string UserId = ponline->UserId;
		//关联实名
		const NbPsmRealNameInfo * preal=realname->GetRealName(ponline->UserId);		
		//上传
		DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();

		dcc->PostBBSLog(roller,UnitCode,preal,ponline);

        //2015/10/23  --shixk
        if(preal == NULL) 
        {
            DebugLog::Log(5, "wangyi PostBbsLog won't be invoked 'cause preal == NULL.\n");
            preal = realname->GetRealName(ponline->Rlinfo.Uid);
            if(preal == NULL) 
                DebugLog::Log(5, "wangyi PostBbsLog still won't be invoked 'cause preal == NULL.\n");
            else
            {
                DebugLog::Log(5, "wangyi This time--PostBbsLog will be invoked 'cause preal != NULL.\n");
                Psm2WmcCommu::GetInstance()->PostBbsLog(UnitCode, preal, ponline, &roller);
            }
        }
        else 
        {
            DebugLog::Log(5, "wangyi PostBbsLog will be invoked 'cause preal != NULL.\n");
            Psm2WmcCommu::GetInstance()->PostBbsLog(UnitCode, preal, ponline, &roller);
        }

        //--shixk
	}else{		
		//上传
		DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();

		dcc->PostBBSLog(roller,UnitCode,NULL,ponline);
	}

	DebugLog::Log(4, "DisposeWangyiBlog:BBSRollerLogDispose Posturl[%s], LinkUrl[%s], proto[%d], bar_name[%s], title[%s], "
            "subtitle[%s], content[%s], domain[%s], action[%d], sender[%s], replyer[%s]\n",
            roller.Posturl.c_str(), roller.LinkUrl.c_str(), roller.proto, roller.bar_name.c_str(), roller.title.c_str(),
            roller.subtitle.c_str(), roller.content.c_str(), roller.domain.c_str(), roller.Action, roller.Sender.c_str(), roller.Replyer.c_str()
	);
	//构造虚拟身份日志
	if(!strvid.empty()){
		// 虚拟身份业务
		VidLog vidlog;
		vidlog.AppProtocol = 20013; //特殊处理
		vidlog.Host = vlog->Host;
		vidlog.LogID = vlog->LogID;
		vidlog.ServiceType = vlog->ServiceType;
		vidlog.Time = vlog->Time;
		vidlog.Account = strvid;
		vidlog.Domain = vlog->Domain;
		vidlog.Nickname = "";
		vidlog.Password = "";
		vidlog.Url = vidlog.Domain;
		vidlog.Action = roller.Action;

		ConvertCode(LCCT_UTF8, vidlog.Account);

		DebugLog::Log(3, "发现web虚拟身份 VidLog: UnitCode[%s], Account[%s], Action[%d], Domain[%s], Nickname[%s], Password[%s], Url[%s], "
			"AppProtocol[%d], Host[%s], LogID[%s], ServiceType[%d], Time[%s]\n",
			UnitCode.c_str(), vidlog.Account.c_str(), vidlog.Action, vidlog.Domain.c_str(), vidlog.Nickname.c_str(), vidlog.Password.c_str(), vidlog.Url.c_str(),
			vidlog.AppProtocol, vidlog.Host.c_str(), vidlog.LogID.c_str(), vidlog.ServiceType, vidlog.Time.c_str()
			);
		// 调用虚拟身份处理逻辑
		VirtualIDDeal((void *)&vidlog);
	}

	
	
}


/*
	samuel 2014-09-20
	disposed some phone info,just for test...wtf!
	url:
	actionContent:
	contentlen:
	action: 0=get 1=post
	return:NULL
*/
void PublicPlaceImplementation::DisposePhoneInfo(const HttpValueLog* vlog,const string& url, const char* actionContent,unsigned int contentlen,int action)
{
	//此函数是临时增加以处理手机信息
	//凡客 android-api.vancl.com/mobileInfo/addMobileInfo
	//内容字段imsiCode=460017560685686 imeiCode=865411010805300

	if(actionContent == NULL || contentlen == 0) return;

	//phone info 
	MobileDeviceLog mobileLog;		

	if(url.compare("android-api.vancl.com/mobileInfo/addMobileInfo") == 0){
		//凡客
		ClipFlag(actionContent,contentlen,"imsiCode=","&",mobileLog.Imsi);
		ClipFlag(actionContent,contentlen,"imeiCode=","&",mobileLog.Imei);	
	}else if(url.compare("api.m.paipai.com/api/user/getUserInfo.xhtml") == 0){
		//拍拍网
		ClipFlag(actionContent,contentlen,"mk=0-","&",mobileLog.Imei);
	}else if(url.compare("mservice.dangdang.com/index.php") == 0){
		//当当
		ClipFlag(actionContent,contentlen,"imei=","&",mobileLog.Imei);	
		ClipFlag(actionContent,contentlen,"model=","&",mobileLog.Model);	
		ClipFlag(actionContent,contentlen,"os_version=","&",mobileLog.OSVersion);
		ClipFlag(actionContent,contentlen,"user_client=","&",mobileLog.OS);
	}else if(url.compare("api.m.taobao.com/rest/api3.do") == 0){
		//淘宝
		ClipFlag(actionContent,contentlen,"imei=","&",mobileLog.Imei);	
		ClipFlag(actionContent,contentlen,"imsi=","&",mobileLog.Imsi);	
		ClipFlag(actionContent,contentlen,"taobao_android_","&",mobileLog.OSVersion);
		ClipFlag(actionContent,contentlen,"taobao_","&",mobileLog.OS);
	}else if(url.compare("gw.m.360buy.com/client.action") == 0){
		//京东，比较特殊，数据包里有内容，不处理，应该处理get头的url
		ClipFlag(vlog->Url.c_str(),vlog->Url.length(),"uuid=","-",mobileLog.Imei);
		ClipFlag(vlog->Url.c_str(),vlog->Url.length(),"client=","&",mobileLog.OS);
		ClipFlag(vlog->Url.c_str(),vlog->Url.length(),"osVersion=","&",mobileLog.OSVersion);
	}
	else{
		//nothing match ,return
		return;
	}

	//由于跟淘宝相同host，去掉
	//else if(url.compare("api.m.taobao.com/rest/api3.do") == 0 || url.compare("op.wangxin.taobao.com/userconfig/get") == 0){
	//	//阿里巴巴
	//	ClipFlag(actionContent,contentlen,"imsiCode=","&",mobileLog.Imsi);
	//	ClipFlag(actionContent,contentlen,"imeiCode=","&",mobileLog.Imei);
	//	ClipFlag(actionContent,contentlen,"phone=","&",mobileLog.OS);
	//	ClipFlag(actionContent,contentlen,"osver=","&",mobileLog.OSVersion);
	//}

	mobileLog.Time = time(NULL);

	//测试数据
	//mobileLog.OS="Android";
	//mobileLog.OSVersion="4.0.3";
	//mobileLog.Manufacturer="Lenovo";
	//mobileLog.Model="A750";
	//关键字段没有获取，不进行上传
	if(mobileLog.Imei.empty()) return;
	//上传
	//关联在线用户记录
	const NbPsmOnlineUserInfo *ponline = onlineuser->GetOnlineUser(vlog->Host,UnitCode);
	if(ponline !=NULL){		
		string UserId = ponline->UserId;
		//关联实名
		const NbPsmRealNameInfo * preal = realname->GetRealName(ponline->UserId);
		//上传
		DanalCenterCommBase *dcc = DanalCenterCommBase::GetDanalCenterCommInstance();
		dcc->PostMobileDeviceInfo(mobileLog,UnitCode,preal,ponline);
	}else{
		//上传
		DanalCenterCommBase *dcc = DanalCenterCommBase::GetDanalCenterCommInstance();
		dcc->PostMobileDeviceInfo(mobileLog,UnitCode,NULL,ponline);
	}
       DebugLog::Log(5,"DisposePhoneInfo 发现IMEI[%s] IMSI[%s] OS[%s] OSVersion[%s]   Manufacturer[%s] Model[%s] 获取时间[%d]\n",
	   	mobileLog.Imei.c_str(), mobileLog.Imsi.c_str() ,mobileLog.OS.c_str(),mobileLog.OSVersion.c_str(),mobileLog.Manufacturer.c_str(),mobileLog.Model.c_str(),mobileLog.Time
	 );
	

}

void PublicPlaceImplementation::ClipFlag(const char* content,unsigned int contentlen,const string& stFlag,const string& endFlag,string& outValue)
{
	char* imsi_start = (char*)strstr(content,stFlag.c_str());
	if(imsi_start == NULL) return;
	char* imsi_end	 = strstr(imsi_start,endFlag.c_str());
	if(imsi_end == NULL) return;
	int imsi_len = imsi_end - imsi_start - stFlag.length();
	outValue.assign(imsi_start + stFlag.length(),imsi_len);
}

void PublicPlaceImplementation::BBSRollerLogDispose(BbsRoller *log,void *user)
{
	PublicPlaceImplementation *This = (PublicPlaceImplementation *)user;
	//This->VirtualIDDeal(log);
	//做bbs还原业务
	//关联在线用户记录
	const NbPsmOnlineUserInfo *ponline=This->onlineuser->GetOnlineUser(log->Host,This->UnitCode);

	if(ponline !=NULL){
		//关联实名
		const NbPsmRealNameInfo * preal=This->realname->GetRealName(ponline->Rlinfo.Uid);
		//const NbPsmRealNameInfo * preal=This->realname->GetRealName(ponline->UserId);
		//报警//?
		This->myPolicy->lock.Lock();
		This->myPolicy->Apply(*log,FLOG_BBS_ROLLER,preal,ponline,This->UnitCode);
		This->myPolicy->lock.UnLock();
		
		//上传
		
		DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();
		dcc->PostBBSLog(*log,This->UnitCode,preal,ponline);
        //2015/10/18 -shixk bbslog 
        if(preal == NULL) DebugLog::Log(5, "preal == NULL, PostBbsLog won't be invoked.\n");
        else DebugLog::Log(5, "preal != NULL, PostBbsLog will be invoked.\n");
        Psm2WmcCommu::GetInstance()->PostBbsLog(This->UnitCode, preal, ponline, log);
        //--shixk
	}else{
		//报警//?
		This->myPolicy->lock.Lock();
		This->myPolicy->Apply(*log,FLOG_BBS_ROLLER,NULL,ponline,This->UnitCode);
		This->myPolicy->lock.UnLock();
		
		//上传
		
		DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();
		dcc->PostBBSLog(*log,This->UnitCode,NULL,ponline);
	}	

	DebugLog::Log(4, "BBSRollerLogDispose Host[%s], Posturl[%s], LinkUrl[%s], proto[%d], bar_name[%s], title[%s], "
            "subtitle[%s], content[%s], domain[%s], action[%d], sender[%s], replyer[%s]\n",
            log->Host.c_str(), log->Posturl.c_str(), log->LinkUrl.c_str(), log->proto, log->bar_name.c_str(), log->title.c_str(),
            log->subtitle.c_str(), log->content.c_str(), log->domain.c_str(), log->Action, log->Sender.c_str(), log->Replyer.c_str()
	);

	// 将数据存入数据库
	StoreData *sd = StoreData::GetInstance();
	string UserId = "";
	if(NULL != ponline){
		UserId = ponline->UserId;
	}
	sd->LogSave(*log, UserId);
}
	//BBSHandle mBBSHandle;
void PublicPlaceImplementation::WebMailRollerLogDispose(WebmailRoller *log,void *user)
{
    DebugLog::Log(5, "PublicPlaceImplementation::WebMailRollerLogDispose.\n");
	PublicPlaceImplementation *This = (PublicPlaceImplementation *)user;
	//拆分虚拟身份信息。做虚拟身份业务 soso
	if(strstr(log->Domain.c_str(),"mail.126.com") || strstr(log->Domain.c_str(),"mail.163.com") || strstr(log->Domain.c_str(),"mail.qq.com") || strstr(log->Domain.c_str(),"mail.sohu.com")){
		VidLog vidlog;
		if(strstr(log->Domain.c_str(),"mail.126.com")){
			vidlog.AppProtocol = PROTO_CODE_WEBMAIL_126; 
			vidlog.Url = "mail.126.com";
		}else if(strstr(log->Domain.c_str(),"mail.163.com")){
			vidlog.AppProtocol = PROTO_CODE_WEBMAIL_163;
			vidlog.Url = "mail.163.com";
		}else if(strstr(log->Domain.c_str(),"mail.qq.com")){
			vidlog.AppProtocol = PROTO_CODE_WEBMAIL_QQ;
			vidlog.Url = "mail.qq.com";	
		}else if(strstr(log->Domain.c_str(),"mail.sohu.com")){
			vidlog.AppProtocol = PROTO_CODE_WEBMAIL_SOHU;
			vidlog.Url = "mail.sohu.com";				
		}else{
		
		}
		vidlog.Host = log->Host;
		vidlog.LogID = log->LogID;
		vidlog.ServiceType = 1;//固定为web
		vidlog.Time = log->Time;
		vidlog.Account = log->sender.c_str();
		vidlog.Domain = log->Domain;
		vidlog.Nickname = "";
		vidlog.Password = "";
		vidlog.Action = 0 ;
		DebugLog::Log(3, "由发送邮件拆分出web虚拟身份 VidLog:  Account[%s], Action[%d], Domain[%s], Nickname[%s], Password[%s], Url[%s], "
		"AppProtocol[%d], Host[%s], LogID[%s], ServiceType[%d], Time[%s]\n",vidlog.Account.c_str(), vidlog.Action, vidlog.Domain.c_str(), vidlog.Nickname.c_str(), vidlog.Password.c_str(), vidlog.Url.c_str(),
		vidlog.AppProtocol, vidlog.Host.c_str(), vidlog.LogID.c_str(), vidlog.ServiceType, vidlog.Time.c_str());
		This->VirtualIDDeal((void *)&vidlog);// 调用虚拟身份处理逻辑
	}
	//做webmail还原业务
	//关联在线用户记录
	const NbPsmOnlineUserInfo *ponline=This->onlineuser->GetOnlineUser(log->Host,This->UnitCode);
	const NbPsmRealNameInfo * preal;
    if(ponline !=NULL){
        //关联实名
        preal=This->realname->GetRealName(ponline->UserId);
        //报警//?
        This->myPolicy->lock.Lock();
        This->myPolicy->Apply(*log,FLOG_WEBMAIL_ROLLER,preal,ponline,This->UnitCode);
        This->myPolicy->lock.UnLock();

        //上传

        DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();
        dcc->PostWebMailExt(*log,This->UnitCode,preal,ponline);
        //2015/10/18 --shixk webmail 
        if( preal == NULL ) 
        {
            preal=This->realname->GetRealName(ponline->Rlinfo.Uid);
        } if(preal != NULL)
        {
            DebugLog::Log(5, "2 PostWebmailLog will be invoked 'cause preal != NULL\n"); 
            Psm2WmcCommu::GetInstance()->PostWebmailLog(This->UnitCode, preal, ponline, log);
        } else
        {
            preal=This->realname->GetRealName(ponline->Rlinfo.Uid);
            DebugLog::Log(5, "2 PostWebmailLog won't be invoked 'cause preal == NULL\n"); 
        }
    }else{
		//报警//?
		This->myPolicy->lock.Lock();
		This->myPolicy->Apply(*log,FLOG_WEBMAIL_ROLLER,NULL,ponline,This->UnitCode);
		This->myPolicy->lock.UnLock();
		
		//上传
		DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();
		dcc->PostWebMailExt(*log,This->UnitCode,NULL,ponline);
	}
	DebugLog::Log(4, "WebMailRollerLogDispose: Host[%s], subject[%s], proto[%d], content[%s], sender[%s], Receipts[%s]\n",
		log->Host.c_str(), log->subject.c_str(), log->proto, log->content.c_str(), log->sender.c_str(), log->Receipts.c_str());

	vector<FileNameT>::iterator it = log->Attachments.begin();
	for(;it!=log->Attachments.end();++it){
		DebugLog::Log(4, "WebMailRollerLogDispose 邮件附带附件:subject[%s],Attachment[%s],UploadName[%s](空表示附件没有获取到)\n",
          log->subject.c_str(), it->RealName.c_str(), it->UploadName.c_str());
	}
	// 将数据存入数据库
	StoreData *sd = StoreData::GetInstance();
	string UserId = "";
	if(NULL != ponline){
		UserId = ponline->UserId;
	}
	sd->LogSave(*log, UserId);
}

void PublicPlaceImplementation::WeiboRollerDispose(WeiboRoller *log, void *user)
{
    PublicPlaceImplementation *This = (PublicPlaceImplementation *)user;

    //关联在线用户记录
    const NbPsmOnlineUserInfo *ponline=This->onlineuser->GetOnlineUser(log->Host,This->UnitCode);
    const NbPsmRealNameInfo * preal= NULL;
    if(ponline !=NULL){
        //关联实名
        preal=This->realname->GetRealName(ponline->UserId);
        //2015/10/18 --shixk
        if(preal == NULL) DebugLog::Log(5, "preal == NULL, PostWeiboLog won't be invoked.\n");
        else 
        {
            DebugLog::Log(5, "preal != NULL, PostWeiboLog will be invoked.\n");
            Psm2WmcCommu::GetInstance()->PostWeiboLog(This->UnitCode, preal, ponline, log);
        }
        //--shixk
    }	

    // 报警
    This->myPolicy->lock.Lock();
    This->myPolicy->Apply(*log,FLOG_WEIBO_ROLLER,preal,ponline,This->UnitCode);
    This->myPolicy->lock.UnLock();


    // 上传
    DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();
    dcc->PostWeibo(*log,This->UnitCode,preal,ponline);


    DebugLog::Log(4, "WeiboRollerLogDispose Host[%s],  AppProtocol[%d], Content[%s], Action[%d], Sender[%s], Replyer[%s]\n",
            log->Host.c_str(), log->AppProtocol, log->Content.c_str(), log->Action, log->Sender.c_str(), log->Replyer.c_str());


}

void PublicPlaceImplementation::WebMailAttRollerDispose(WebmailAttRoller *log, void *user)
{
    PublicPlaceImplementation *This = (PublicPlaceImplementation *)user;
	DebugLog::Log(4, "WebMailAttRollerDispose上传附件文件: Proto[%d], SourceName[%s], UnipName[%s]\n", log->proto, log->RealName.c_str(), log->LocalPath.c_str());
    //上传附件
    DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();
	dcc->UploadFile(log->LocalPath, This->UnitCode);
    return;
}


void PublicPlaceImplementation::EmailDeal(void *log)
{	
	NetLogBaseInfo *vlog=(NetLogBaseInfo *)log;
	if(mhttpEmail->LogInbufer(vlog) == 0){
		return;
	}
	
	vlog=mhttpEmail->GetBufer();

	//return ;

	WebmailRoller wmail;
	
	/** 分析邮件内容 */
	EmailEntity ee;
	EmailParse ep;
	ep.DisposEmailContent((char *)((MailRollerLog*)vlog)->EmailData.c_str()
				,(int)((MailRollerLog*)vlog)->EmailData.size(),&ee);

	
	// return;
	string fullpath;
	string bsname;
	//保存Email文件
	int ret = GenFileName(log, fullpath, bsname);
	if(ret!=0){
		return;
	}
	ret=WriteToFile(fullpath, (void *)vlog);
	if(ret!=0){
		return;
	}

	//上报email
	DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();
	if(dcc==NULL){
		return;
	}


	//上传文件
	dcc->UploadFile(fullpath,UnitCode);

	//vlog->Host="192.168.51.23";
	//关联在线用户记录
	const NbPsmOnlineUserInfo *ponline=onlineuser->GetOnlineUser(vlog->Host,UnitCode);

	// liujl add
	const NbPsmRealNameInfo * preal = NULL;

	if(ponline !=NULL){
		//关联实名
		preal=realname->GetRealName(ponline->UserId);
		
		dcc->PostMailAccess(vlog,ee,bsname,UnitCode,preal,ponline);
	}else{
		//上报email
		dcc->PostMailAccess(vlog,ee,bsname,UnitCode,NULL,ponline);
	}

	char strtime[32]={0};
	GetTime(strtime);
	wmail.content=ee.MainContent;
	wmail.sender=ee.Sender;
	wmail.subject=ee.Subject;
	wmail.AppProtocol=vlog->AppProtocol;
	wmail.Domain=vlog->Domain;
	wmail.DstHost=vlog->DstHost;
	wmail.DstMac=vlog->DstMac;
	wmail.DstPort=vlog->DstPort;
	wmail.Host=vlog->Host;
	wmail.LogID=vlog->LogID;
	//wmail.proto=vlog->AppProtocol;
	wmail.ProxyIp=vlog->ProxyIp;
	wmail.proxyPort=vlog->proxyPort;
	wmail.ProxyType=vlog->ProxyType;
	wmail.ServiceType=vlog->ServiceType;
	wmail.SrcHost=vlog->SrcHost;
	wmail.SrcMac=vlog->SrcMac;
	wmail.SrcPort=vlog->SrcPort;
	wmail.Time=vlog->Time;
	if(vlog->Time==""){
		wmail.Time=strtime;
	}
	wmail.TransPotocol=vlog->TransPotocol;
	DebugLog::Log(4, "EmailDeal Host[%s], MailFile[%s] subject[%s], sender[%s],  content[%s], Time[%s]\n",
		vlog->Host.c_str(), fullpath.c_str(), wmail.subject.c_str(), wmail.sender.c_str(), wmail.content.c_str(), wmail.Time.c_str());
    
   /////// 
    vector<string>::iterator iter = ee.Receiver.begin();
    int i = 1;
    DebugLog::Log(5, "coco ReceiverNum:[%d]\n", ee.Receiver.size());
    for(;iter != ee.Receiver.end(); iter++)
    {
        wmail.Receipts += *iter;
        if((iter+1) != ee.Receiver.end())
            wmail.Receipts += ",";
        DebugLog::Log(5, "coco Receiver[%i]:[%s]\n", i++, iter->c_str());
    }
    DebugLog::Log(5, "coco Receiver:[%s]\n", wmail.Receipts.c_str());
	//报警
	myPolicy->lock.Lock();
	this->myPolicy->Apply(wmail,FLOG_WEBMAIL_ROLLER,preal,ponline,UnitCode);
	myPolicy->lock.UnLock();

    //2015/10/18 --shixk postmail coco
	if(vlog->Time==""){
        GetTime4Wmc(strtime);
		wmail.Time=strtime;
	}
    DebugLog::Log(5, "coco wmail.Time:[%s]\n", wmail.Time.c_str());
    if(preal != NULL)
    {
        DebugLog::Log(5, "preal != NULL, PostMailLog will be invoked.\n");
        Psm2WmcCommu::GetInstance()->PostMailLog(UnitCode, preal, ponline, &wmail, fullpath);
    }
    else
    {
        DebugLog::Log(5, "preal == NULL using UserId, try Rlinfo.Uid.\n");
		preal=realname->GetRealName(ponline->Rlinfo.Uid);
        if(preal != NULL) 
            Psm2WmcCommu::GetInstance()->PostMailLog(UnitCode, preal, ponline, &wmail, fullpath);
    }
}

void PublicPlaceImplementation::KeywordDeal(void *log)
{
    DebugLog::Log(5, "PostSearchKeywordLog will be invoked if preal not null.\n");
	SearchKeyword *vlog=(SearchKeyword *)log;
	//编码转换
	ConvertCode(vlog->KeyWordCodeType,vlog->Keyword);
	DebugLog::Log(4, "KeywordDeal code type[%d], keyword[%s]\n", (int)vlog->KeyWordCodeType, vlog->Keyword.c_str());
	//关联在线用户记录
	const NbPsmOnlineUserInfo *ponline=onlineuser->GetOnlineUser(vlog->Host,UnitCode);	
	
	//关联实名
	const NbPsmRealNameInfo * preal=NULL;
	string UserId = "";
	char strtime[64] = {0};
	time_t current = time(NULL);
	vlog->Time = z_time_t2str(strtime, &current, ZTIMESTR_TYPE1);

	if(ponline !=NULL){
        //DebugLog::Log(4, "在线用户存在\n");
		UserId = ponline->UserId;
		//关联实名
		preal=realname->GetRealName(ponline->Rlinfo.Uid);
		//报警
		myPolicy->lock.Lock();
		this->myPolicy->Apply(*vlog,FLOG_SEARCH_KEYWORD,preal,ponline,UnitCode);
		myPolicy->lock.UnLock();
		
		//上传
		DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();
		dcc->PostKeyword(*vlog,UnitCode,preal,ponline);
        //2015/10/22 --shixk
        if(preal != NULL)
        {
            DebugLog::Log(5, "PostSearchKeywordLog will be invoked 'cause preal not null.\n");
            Psm2WmcCommu::GetInstance()->PostSearchKeywordLog(UnitCode, preal, ponline, vlog);
        }
        //--shixk
	}else{
	    //DebugLog::Log(4, "在线用户不存在!\n");
		//报警
		myPolicy->lock.Lock();
		this->myPolicy->Apply(*vlog,FLOG_SEARCH_KEYWORD,NULL,ponline,UnitCode);
		myPolicy->lock.UnLock();
		
		//上传
		DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();
		dcc->PostKeyword(*vlog,UnitCode,NULL,ponline);
	}	


	static StoreData* sd = StoreData::GetInstance();
	sd->LogSave(*vlog, UserId);
}

void PublicPlaceImplementation::ChatDeal(void *log)
{
	ImMsgLog *vlog=(ImMsgLog *)log;
	char strtime[64] = {0};
	time_t current = time(NULL);
	vlog->Time = z_time_t2str(strtime, &current, ZTIMESTR_TYPE1);

	//编码转换
	ConvertCode(vlog->MessageCodeType,vlog->Message);

	//关联在线用户记录
	const NbPsmOnlineUserInfo *ponline=onlineuser->GetOnlineUser(vlog->Host,UnitCode);

	const NbPsmRealNameInfo * preal = NULL;

	if(ponline !=NULL){
		//关联实名
		preal=realname->GetRealName(ponline->UserId);

		//报警
		myPolicy->lock.Lock();
		this->myPolicy->Apply(*vlog,FLOG_IMMSG,preal,ponline,UnitCode);
		myPolicy->lock.UnLock();
		
		//上传
		DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();
		dcc->PostChat(*vlog,UnitCode,preal,ponline);
		if(preal != NULL)
				//2015/10/18 --shixk
				Psm2WmcCommu::GetInstance()->PostChatLog(UnitCode, preal, ponline, vlog);
		//--shixk

	}else{
		//报警
		myPolicy->lock.Lock();
		this->myPolicy->Apply(*vlog,FLOG_IMMSG,preal,ponline,UnitCode);
		myPolicy->lock.UnLock();
		
		//上传
		DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();
		dcc->PostChat(*vlog,UnitCode,NULL,ponline);
	}	
	
	// 将数据存入数据库
	StoreData *sd = StoreData::GetInstance();
	string UserId;
	if(NULL != ponline){
		UserId = ponline->UserId;
	}else{
		UserId = "";
	}
	sd->LogSave(*vlog, UserId);
}

void PublicPlaceImplementation::GroupChatDeal(void *log)
{
	GroupMsgLog *vlog=(GroupMsgLog *)log;

	//编码转换
	ConvertCode(vlog->MessageCodeType,vlog->Message);
	//关联在线用户记录
	const NbPsmOnlineUserInfo *ponline=onlineuser->GetOnlineUser(vlog->Host,UnitCode);
	const NbPsmRealNameInfo * preal = NULL;
	if(ponline != NULL){
		//关联实名
		preal=realname->GetRealName(ponline->Rlinfo.Uid);

		//报警
		myPolicy->lock.Lock();
		this->myPolicy->Apply(*vlog,FLOG_GROUPMSG,preal,ponline,UnitCode);
		myPolicy->lock.UnLock();
		
		//上传
		
		DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();
		dcc->PostGroupChat(*vlog,UnitCode,preal,ponline);
		if(preal != NULL)
				//2015/10/19 --shixk
				Psm2WmcCommu::GetInstance()->PostGroupChatLog(UnitCode, preal, ponline, vlog); 
		//--shixk
	}else{
		//报警
		myPolicy->lock.Lock();
		this->myPolicy->Apply(*vlog,FLOG_GROUPMSG,NULL,ponline,UnitCode);
		myPolicy->lock.UnLock();
		
		//上传
		DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();
		dcc->PostGroupChat(*vlog,UnitCode,NULL,ponline);
	}	
}

void PublicPlaceImplementation::FlowDeal(void *log)
{
	FlowsLog *vlog=(FlowsLog *)log;

	//关联在线用户记录
	const NbPsmOnlineUserInfo *ponline=onlineuser->GetOnlineUser(vlog->Host,UnitCode);
	if(ponline !=NULL){
		//关联实名
		const NbPsmRealNameInfo * preal=realname->GetRealName(ponline->Rlinfo.Uid);
		//报警
		myPolicy->lock.Lock();
		this->myPolicy->Apply(*vlog,FLOG_FLOWS,preal,ponline,UnitCode);
		myPolicy->lock.UnLock();
		
		//上传
		DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();
		dcc->PostFlowLog(*vlog,UnitCode,preal,ponline);
	}else{
		//报警
		myPolicy->lock.Lock();
		this->myPolicy->Apply(*vlog,FLOG_FLOWS,NULL,ponline,UnitCode);
		myPolicy->lock.UnLock();
		
		//上传
		DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();
		dcc->PostFlowLog(*vlog,UnitCode,NULL,ponline);
	}	
}

void PublicPlaceImplementation::SimpAccessDeal(void *log)
{
	SimpAccessLog *vlog=(SimpAccessLog *)log;

	//关联在线用户记录
	const NbPsmOnlineUserInfo *ponline=onlineuser->GetOnlineUser(vlog->Host,UnitCode);
    const NbPsmRealNameInfo * preal=NULL;
	if(ponline !=NULL){
		//关联实名
		preal=realname->GetRealName(ponline->Rlinfo.Uid);
		//报警
		myPolicy->lock.Lock();
		this->myPolicy->Apply(*vlog,FLOG_OTHER_ACCESS,preal,ponline,UnitCode);
		myPolicy->lock.UnLock();
		
		//上传
		DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();
		dcc->PostOtherAccess(*vlog,UnitCode,preal,ponline);
	}else{
		//报警
		myPolicy->lock.Lock();
		this->myPolicy->Apply(*vlog,FLOG_OTHER_ACCESS,NULL,ponline,UnitCode);
		myPolicy->lock.UnLock();
		
		//上传
		DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();
		dcc->PostOtherAccess(*vlog,UnitCode,NULL,ponline);
	}
    //2015/10/19 --shixk
    //Psm2WmcCommu::GetInstance()->PostAccessRecordLog SimpAccessLog ????? upload or not
}

void PublicPlaceImplementation::VidTelNoDeal(void *log)
{
	VidTelNOLog *vlog=(VidTelNOLog *)log;
	string UserId = "";
	char cur[32] = {0};
	z_gettimestr(cur, ZTIMESTR_TYPE1);
	vlog->Time = cur;

	//关联在线用户记录
	const NbPsmOnlineUserInfo *ponline=onlineuser->GetOnlineUser(vlog->Host,UnitCode);
	if(ponline !=NULL){
		UserId = ponline->UserId;
		
		//关联实名
		const NbPsmRealNameInfo * preal=realname->GetRealName(ponline->UserId);
		//报警
		myPolicy->lock.Lock();
		this->myPolicy->Apply(*vlog,FLOG_TELNO,preal,ponline,UnitCode);
		myPolicy->lock.UnLock();
		
		//上传
		DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();

		dcc->PostVidTelNo(*vlog,UnitCode,preal,ponline);
	}else{
		//报警
		myPolicy->lock.Lock();
		this->myPolicy->Apply(*vlog,FLOG_TELNO,NULL,ponline,UnitCode);
		myPolicy->lock.UnLock();
		
		//上传
		DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();

		dcc->PostVidTelNo(*vlog,UnitCode,NULL,ponline);
	}

	static StoreData* sd = StoreData::GetInstance();
	sd->LogSave(*vlog, UserId);
}

int PublicPlaceImplementation::OffLine(const char * unitcode,const char *ip)
{
	VidLog vl;
	char sql[1024]={0};
	char *buf[15];
	sprintf(sql,"select * from vid where unitcode='%s' and Host='%s';",unitcode,ip);
	Database *db=CreateDatabase();
	if(db ==NULL){
		DebugLog::Log(0, "OffLine: db=NULL 数据库对象创建失败 !\n");
		return 0;
	}
	if(db->connect() !=0){
		DebugLog::Log(0, "OffLine: db->connect 数据库连接失败 !\n");
		db->close();
		DestroyDatabase(db);
		return 0;
	}
	if(db->find(sql)<0){
		db->close();
		DestroyDatabase(db);
		return 1;
	}

	while(db->fetch() ==0){
		db->bind(buf,15);
		vl.Account=buf[3];
		vl.Action=atoi(buf[8]);
		vl.AppProtocol=atoi(buf[9]);
		vl.Domain=buf[5];
		vl.Host=ip;
		vl.LogID=buf[2];
		vl.Nickname=buf[6];
		vl.Password=buf[4];
		vl.ServiceType=atoi(buf[11]);
		vl.Time=buf[12];
		vl.Url=buf[7];
		
		OffVid(vl,UnitCode);
	}
	sprintf(sql,"delete from vid where unitcode='%s' and Host='%s';", unitcode, ip);
	db->query(sql);
	db->close();
	DestroyDatabase(db);
	return 0;

}

int PublicPlaceImplementation::GetVid(const string &UnitCode, const string &IP, int Protocol, VidLog &Vid)
{
	VidLog vl;
	char sql[1024]={0};
	char *buf[15];
	sprintf(sql,"select * from vid where unitcode='%s' and Host='%s';",UnitCode.c_str(), IP.c_str());
	Database *db=CreateDatabase();
	if(db ==NULL){
		DebugLog::Log(0, "OffLine: db=NULL 数据库对象创建失败 !\n");
		return -1;
	}
	if(db->connect() !=0){
		DebugLog::Log(0, "OffLine: db->connect 数据库连接失败 !\n");
		db->close();
		DestroyDatabase(db);
		return -1;
	}
	if(db->find(sql)<0){
		db->close();
		DestroyDatabase(db);
		return -1;
	}

	while(db->fetch() ==0){
		db->bind(buf,15);
		vl.Account=buf[3];
		vl.Action=atoi(buf[8]);
		vl.AppProtocol=atoi(buf[9]);
		vl.Domain=buf[5];
		vl.Host=IP;
		vl.LogID=buf[2];
		vl.Nickname=buf[6];
		vl.Password=buf[4];
		vl.ServiceType=atoi(buf[11]);
		vl.Time=buf[12];
		vl.Url=buf[7];
		if(vl.AppProtocol == Protocol){
			Vid = vl;
			return 0;
		}
	}
	return -1;
}

int PublicPlaceImplementation::OnlineVid(const char * unitcode,const char *ip)
{
	VidLog vl;
	char sql[1024]={0};
	char *buf[15];
	sprintf(sql,"select * from vid where unitcode='%s' and Host='%s' and onlineid is NULL and realnameid is NULL;",unitcode,ip);
	Database *db=CreateDatabase();
	if(db ==NULL){
		DebugLog::Log(0, "OnlineVid: db=NULL 数据库对象创建失败 !\n");
		return 0;
	}
	if(db->connect() !=0){
		DebugLog::Log(0, "OnlineVid: db->connect 数据库连接失败 !\n");
		db->close();
		DestroyDatabase(db);
		return 0;
	}

	if(db->find(sql)<0){
		db->close();
		DestroyDatabase(db);
		return 1;
	}

	while(db->fetch() ==0){
		db->bind(buf,15);
		vl.Account=buf[3];
		vl.Action=atoi(buf[8]);
		vl.AppProtocol=atoi(buf[9]);
		vl.Domain=buf[5];
		vl.Host=ip;
		vl.LogID=buf[2];
		vl.Nickname=buf[6];
		vl.Password=buf[4];
		vl.ServiceType=atoi(buf[11]);
		vl.Time=buf[12];
		vl.Url=buf[7];
		
		VirtualIDDeal((void *)&vl);
	}
	sprintf(sql,"delete from vid where unitcode='%s' and Host='%s';", unitcode, ip);
	db->query(sql);
	db->close();
	DestroyDatabase(db);

	return 0;
}

void PublicPlaceImplementation::OffVid(const VidLog &vlog,const string &unitcode)
{
	//const NbPsmRealNameInfo * preal=realname->GetRealName(vlog.Host);

	//关联在线用户记录
	const NbPsmOnlineUserInfo *ponline=onlineuser->GetOnlineUser(vlog.Host,UnitCode);
	if(ponline !=NULL){
		//关联实名
		const NbPsmRealNameInfo * preal=realname->GetRealName(ponline->UserId);
		//报警
		myPolicy->lock.Lock();
		this->myPolicy->Apply(vlog,FLOG_FLOWS,preal,ponline,UnitCode);
		myPolicy->lock.UnLock();
		
		//上传
		DanalCenterCommBase *dcc=DanalCenterCommBase::GetDanalCenterCommInstance();
        //2015/10/26  --shixk
		dcc->PostVidOffLine(vlog,UnitCode,preal,ponline);
        if(preal != NULL)
        {
            DebugLog::Log(5, "ponline & preal != NULL, PostVidLog will be invoked.\n");
            Psm2WmcCommu::GetInstance()->PostVidLog(UnitCode, preal, ponline, &vlog);
        }
        else
        {
            DebugLog::Log(5, "preal == NULL, PostVidLog won't  invoked.\n");
        }
        //--shixk
	}
}

int PublicPlaceImplementation::WriteToFile(const string &filename,void *log)
{
	MailRollerLog *vlog=(MailRollerLog *)log;

	FILE *fp = NULL;
	if (NULL != (fp = fopen(filename.c_str(), "ab+"))) {
		if (fwrite(vlog->EmailData.c_str(), 1,vlog->EmailData.size() , fp) == vlog->EmailData.size()) {
			fclose(fp);
			return 0;
		} else {
			fclose(fp);
			return -1;
		}
	}

	return -1;
}

int PublicPlaceImplementation::GenFileName(void *log, string &fullpath, string &bsname)
{
	static unsigned int no=0;
	MailRollerLog *vlog=(MailRollerLog *)log;
	no++;
	char fullbuf[256]={0};
	char bsbuf[128] = {0};
	char timestr[128]={0};
	char date[128] = {0};
	char dir1[128] = {0};	// 目录1
	char dir2[128] = {0}; 	// 目录2
	char logdir[128] = {0};
#ifdef _WIN32
	strcpy(logdir, "C:\\winfgate_log\\email");
#else
	strcpy(logdir, "/var/zetronic/fgate/mini_hsm/email");
#endif
	GetTime(timestr);
	time_t t = time(NULL);
	struct tm *tm_t;
	tm_t = localtime(&t);
	sprintf(date,  "%04d-%02d-%02d", tm_t->tm_year+1900, tm_t->tm_mon+1, tm_t->tm_mday);
	snprintf(dir1, sizeof(dir1)-1, "%s", logdir);
	snprintf(dir2, sizeof(dir2)-1, "%s%s%s", dir1, DIR_CHAR, date);

#ifdef _WIN32
	if(access(dir1, 0) == -1){
		_mkdir(dir1);
	}
	if(access(dir2, 0) == -1 && _mkdir(dir2) == -1){
		return -1;
	}
#else
	if(access(dir1, 0) == -1){
		mkdir(dir1, S_IRWXU);
	}
	if(access(dir2, 0) == -1 && mkdir(dir2, S_IRWXU) == -1){
		return -1;
	}
#endif
	
	if(vlog->AppProtocol == PROTO_CODE_POP){
		sprintf(bsbuf, "%s_%s_pop3_%u.eml", UnitCode.c_str(),timestr,no);
	}else{
		sprintf(bsbuf, "%s_%s_smtp_%u.eml", UnitCode.c_str(),timestr,no);
	}
	sprintf(fullbuf, "%s%s%s", dir2, DIR_CHAR, bsbuf);

	bsname = bsbuf;
	fullpath = fullbuf;
	return 0;
}

void GetTime4Wmc(char * buf)
{
	time_t t;
	struct tm* tm_t;
	time(&t);
	tm_t=localtime(&t);
	sprintf(buf,"%.4d-%.2d-%.2d %.2d:%.2d:%.2d",tm_t->tm_year+1900,tm_t->tm_mon+1,tm_t->tm_mday,tm_t->tm_hour,tm_t->tm_min,tm_t->tm_sec);
	return ;
}

void GetTime(char * buf)
{
	time_t t;
	struct tm* tm_t;
	time(&t);
	tm_t=localtime(&t);
	sprintf(buf,"%.4d-%.2d-%.2d_%.2d-%.2d-%.2d",tm_t->tm_year+1900,tm_t->tm_mon+1,tm_t->tm_mday,tm_t->tm_hour,tm_t->tm_min,tm_t->tm_sec);
	return ;
}

void PublicPlaceImplementation::CorrectRoomNum(char *RoomNum, size_t Len)
{
	// 旅业接口可能传的房间号是utf8的中文，在这里做一下转换兼容
	string StrRoomNum = RoomNum;
	int ret = 0;
	if(IsGb2312(RoomNum) == 1){	//  本来就是gb2312，不用转换
		return ;
	}
	ret = ConvertCode(LCCT_UTF8, StrRoomNum);

	if(0 == ret && IsGb2312(StrRoomNum.c_str()) == 1){		//  转换出来的字符是gb2312
		memset(RoomNum, 0, Len);
		strncpy(RoomNum, StrRoomNum.c_str(), Len-1);
		return ;
	}

	//  转换出来的字符不是gb2312，则将一个字节转成两个字符
	StrRoomNum.clear();
	StrRoomNum = RoomNum;
	memset(RoomNum, 0, Len);
	for(size_t i = 0; i*2 < Len-2 && i < StrRoomNum.size(); i++){
		sprintf(RoomNum+i*2, "%02X", (unsigned char) StrRoomNum[i]);
	}
}


void PublicPlaceImplementation::HttpCookieDeal(void *log)
{
	HttpCookieLog *clog =(HttpCookieLog *)log;
	int Usage = HttpCookieList::GetInstance()->GetCookieCharactUsage(clog->MatchID);
	if(Usage==0){
		// 关联数据，填入缓存
		mhttpCookie->LogInbufer(clog);
	}else if(Usage==1){
		// 取虚拟身份
		HttpVid vid;
		HttpVidGet *hvgobj = HttpVidGet::Getinstance();
		if(hvgobj == NULL){
			return;
		}
		const string newvalue="&";
		const string oldvalue="; ";
		StrReplaceAll(clog->Content, oldvalue, newvalue);	//将cookie中所有的"; " 转换成"&"
		int ret = 0;
		int TotalLen = clog->Content.length();
		DebugLog::Log(4, "HttpCookieDeal匹配到cookielist名单: MatchID[%d], Usage[%d], CookieContent[%s], Len[%d]\n", clog->MatchID,Usage, clog->Content.c_str(), TotalLen);
		
		//获取host
		string host;
		size_t url_size = clog->Url.find_first_of("?");
		if(url_size == string::npos){
			host = clog->Url;
		}else{
			host.assign(clog->Url.c_str(), url_size);
		}
        // URL解码
        static CodingDecode cdobj;
        const char *str = NULL;
        char *strdecode = cdobj.UrlDecode(clog->Content.c_str(),(unsigned int)clog->Content.size());
        if(!strdecode){
            str = clog->Content.c_str();
        }else{
            str = strdecode;
        }
		
		if(clog->Action == 0 || clog->Action == 1){
			ret = hvgobj->GetVid(host.c_str(),(unsigned int)host.size(),str,(unsigned int)strlen(str),NULL,0,&vid);
		}else{
			ret = hvgobj->GetVid(host.c_str(),(unsigned int)host.size(),NULL,0,str,(unsigned int)strlen(str),&vid);
		}
        
		//ret = hvgobj->GetVid(host.c_str(),(unsigned int)host.size(),NULL,0,str,strlen(str),&vid);
        if(strdecode){
            cdobj.CodeValueFree(strdecode);
        }
		if(ret >= 0){
			// 虚拟身份业务
			VidLog vidlog;
			vidlog.AppProtocol = vid.type;
			vidlog.Host = clog->Host;
			vidlog.LogID = clog->LogID;
			vidlog.ServiceType = clog->ServiceType;
			vidlog.Time = clog->Time;
			vidlog.Account = vid.account;
			vidlog.Domain = clog->Domain;
			vidlog.Nickname = "";
			vidlog.Password = vid.password;
			vidlog.Url = host;
			vidlog.Action = 0;
			//因为cookie的内容会比较多，所只对获取到的account进行url解码
			if(vidlog.Domain == "i.sso.sina.com.cn" ||vidlog.Domain == "beacon.sina.com.cn"){
				static CodingDecode cdobj;
				const char *str = NULL;
				char *strdecode = cdobj.UrlDecode(vidlog.Account.c_str(),(unsigned int)vidlog.Account.size());
				if(!strdecode){
					str = vidlog.Account.c_str();
				}else{
					str = strdecode;
				}
				vidlog.Account.assign(str,strlen(str));			
			}
			ConvertCode(LCCT_UTF8, vidlog.Account);
			DebugLog::Log(3, "通过Cookie发现web虚拟身份 VidLog: UnitCode[%s], Account[%s], Action[%d], Domain[%s], Nickname[%s], Password[%s], Url[%s], "
				"AppProtocol[%d], Host[%s], LogID[%s], ServiceType[%d], Time[%s]\n",
				UnitCode.c_str(), vidlog.Account.c_str(), vidlog.Action, vidlog.Domain.c_str(), vidlog.Nickname.c_str(), vidlog.Password.c_str(), vidlog.Url.c_str(),
				vidlog.AppProtocol, vidlog.Host.c_str(), vidlog.LogID.c_str(), vidlog.ServiceType, vidlog.Time.c_str()
			 );
			// 调用虚拟身份处理逻辑
			VirtualIDDeal((void *)&vidlog);		

		}else{
			DebugLog::Log(4, "HttpCookieDeal通过nbvidlist解析虚拟身份失败! ret[%d]\n", ret);
		}
		//2015/10/19 --shixk
        DebugLog::Log(5, "HttpCookieDeal\n");
        const NbPsmOnlineUserInfo *ponline=onlineuser->GetOnlineUser(clog->Host,UnitCode);
		const NbPsmRealNameInfo * preal= NULL;
        if(ponline != NULL){
            //关联实名
            //const NbPsmRealNameInfo * preal=realname->GetRealName(ponline->UserId);
            const NbPsmRealNameInfo * preal=realname->GetRealName(ponline->Rlinfo.Uid);
            if(preal!=NULL)
            {
                DebugLog::Log(5, "preal==NULL\n");
                Psm2WmcCommu::GetInstance()->PostCookieLog(UnitCode, preal, ponline, clog);
            } 
        }
        else{
            DebugLog::Log(5, "ponline == NULL\n");
        }
		//--shixk
        return ;

	}
}

void PublicPlaceImplementation::GetCookieLog(const string &LogID, void *user, HttpCookieLog &log)
{
	
	PublicPlaceImplementation *This = (PublicPlaceImplementation *)user;
	NetLogBaseInfo *plog = This->mhttpCookie->GetBufer(LogID);
	if(NULL != plog){
		log = *(HttpCookieLog *)plog;
	}
}

int PublicPlaceImplementation::StrReplaceAll(string &Str, const string &OldValue, const string &NewValue )
{
	/*
	for(string::size_type pos(0); pos!=string::npos; pos+=NewValue.length()){
		if((pos = Str.find(OldValue, pos)) != string::npos){
			Str.replace(pos,OldValue.length(), NewValue );
		}else{
			break;
		}
	}
	*/
	
	string::size_type pos(0);
	do {
		if((pos = Str.find(OldValue, pos)) != string::npos){
			Str.replace(pos,OldValue.length(), NewValue );
		}else{
			break;
		}
		pos+=NewValue.length();
	} while(1);
	
	return 0;


}


int PublicPlaceImplementation::DisposeKeyword(HttpValueLog * klog)
{
        DebugLog::Log(5, "2 PublicPlaceImplementation::DisposeKeyword.\n");
		SearchEngine *s = SearchEngine::GetInstance();
		SearchResult cb;
		//传入host和get的value部分
		int kdret =s->Dispose(klog->Domain.c_str(),klog->Content.c_str(),(int)klog->Content.size(),&cb);
		if(kdret >=0){
			SearchKeyword sk;
			sk.AppProtocol = PROTO_CODE_HTTP;
			sk.Host = klog->Host;
			sk.LogID = klog->LogID;
			sk.ServiceType = SERVICE_TYPE_BROWSING;
			sk.Time.clear();
			sk.Keyword = cb.mKeyword;
			if(cb.mIsutf8){
				sk.KeyWordCodeType = LCCT_UTF8;
			}else{
				sk.KeyWordCodeType = LCCT_GB2312;
			}
			sk.SearchEnginetype = (int)cb.mType;
			KeywordDeal((void *)&sk);
		}
            DebugLog::Log(5, "kdret:[%d].\n", kdret);
		return kdret;
}





