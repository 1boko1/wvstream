/*
* libwvstream.cpp
*****************************************************************************
* Copyright (C) 2015, liberty_developer
*
* Email: liberty.developer@xmail.net
*
* This source code and its use and distribution, is subject to the terms
* and conditions of the applicable license agreement.
*****************************************************************************/

// libwvstream.cpp : Defines the exported functions for the DLL application.
//

#include <iostream>
#include <thread>
#include <string.h>
#include <sstream>
#include <deque>
#include <stdarg.h>
#include "dash/DASHTree.h"
#include "dash/DASHStream.h"
#include "cdm/media/cdm/cdm_adapter.h"
#include "../libbento4/Core/Ap4.h"
#include "helpers.h"
#include "../libcurl/include/curl/curl.h"
#include "oscompat.h"

//#define MUXED_STREAM 1

/*******************************************************
						CDM
						********************************************************/

/*----------------------------------------------------------------------
|   CdmDecryptedBlock implementation
+---------------------------------------------------------------------*/

class CdmDecryptedBlock : public cdm::DecryptedBlock {
public:
	CdmDecryptedBlock() :buffer_(0), timestamp_(0) {};
	virtual ~CdmDecryptedBlock() {};

	virtual void SetDecryptedBuffer(cdm::Buffer* buffer) override { buffer_ = buffer; };
	virtual cdm::Buffer* DecryptedBuffer() override { return buffer_; };

	virtual void SetTimestamp(int64_t timestamp) override { timestamp_ = timestamp; };
	virtual int64_t Timestamp() const override { return timestamp_; };
private:
	cdm::Buffer *buffer_;
	int64_t timestamp_;
};

/*----------------------------------------------------------------------
|   CdmDecryptedBlock implementation
+---------------------------------------------------------------------*/
class CdmBuffer : public cdm::Buffer {
public:
	CdmBuffer(AP4_DataBuffer *buffer) :buffer_(buffer) {};
	virtual ~CdmBuffer() {};

	virtual void Destroy() override {};

	virtual uint32_t Capacity() const override
	{
		return buffer_->GetBufferSize();
	};
	virtual uint8_t* Data() override
	{
		return (uint8_t*)buffer_->GetData();
	};
	virtual void SetSize(uint32_t size) override
	{
		buffer_->SetDataSize(size);
	};
	virtual uint32_t Size() const override
	{
		return buffer_->GetDataSize();
	};
private:
	AP4_DataBuffer *buffer_;
};

/*----------------------------------------------------------------------
|   WV_CencSingleSampleDecrypter
+---------------------------------------------------------------------*/
class WV_CencSingleSampleDecrypter : public AP4_CencSingleSampleDecrypter
{
public:
	// methods
	
	WV_CencSingleSampleDecrypter(media::CdmAdapter *adapter) :
		AP4_CencSingleSampleDecrypter(0),
		wv_adapter(adapter),
		max_subsample_count_(0),
		subsample_buffer_(0) {};
	bool initialized()const { return wv_adapter != 0; };
	virtual AP4_Result DecryptSampleData(AP4_DataBuffer& data_in,
		AP4_DataBuffer& data_out,

		// always 16 bytes
		const AP4_UI08* iv,

		// pass 0 for full decryption
		unsigned int    subsample_count,

		// array of <subsample_count> integers. NULL if subsample_count is 0
		const AP4_UI16* bytes_of_cleartext_data,

		// array of <subsample_count> integers. NULL if subsample_count is 0
		const AP4_UI32* bytes_of_encrypted_data);

private:
	media::CdmAdapter *wv_adapter;
	unsigned int max_subsample_count_;
	cdm::SubsampleEntry *subsample_buffer_;
	

};

/*----------------------------------------------------------------------
|   WV_CencSingleSampleDecrypter::DecryptSampleData
+---------------------------------------------------------------------*/
AP4_Result WV_CencSingleSampleDecrypter::DecryptSampleData(
	AP4_DataBuffer& data_in,
	AP4_DataBuffer& data_out,
	const AP4_UI08* iv,
	unsigned int    subsample_count,
	const AP4_UI16* bytes_of_cleartext_data,
	const AP4_UI32* bytes_of_encrypted_data)
{
	// the output has the same size as the input
	data_out.SetDataSize(data_in.GetDataSize());
	if (!wv_adapter)
	{
		data_out.SetData(data_in.GetData(), data_in.GetDataSize());
		return AP4_SUCCESS;
	}

	// check input parameters
	if (iv == NULL) return AP4_ERROR_INVALID_PARAMETERS;
	if (subsample_count) {
		if (bytes_of_cleartext_data == NULL || bytes_of_encrypted_data == NULL) {
			std::cout << "AP4_ERROR_INVALID_PARAMETERS"<< std::endl;
			return AP4_ERROR_INVALID_PARAMETERS;
		}
	}

	// transform ap4 format into cmd format
	cdm::InputBuffer cdm_in;
	if (subsample_count > max_subsample_count_)
	{
		subsample_buffer_ = (cdm::SubsampleEntry*)realloc(subsample_buffer_, subsample_count*sizeof(cdm::SubsampleEntry));
		max_subsample_count_ = subsample_count;
	}
	for (cdm::SubsampleEntry *b(subsample_buffer_), *e(subsample_buffer_ + subsample_count); b != e; ++b, ++bytes_of_cleartext_data, ++bytes_of_encrypted_data)
	{
		b->clear_bytes = *bytes_of_cleartext_data;
		b->cipher_bytes = *bytes_of_encrypted_data;
	}
	cdm_in.data = data_in.GetData();
	cdm_in.data_size = data_in.GetDataSize();
	cdm_in.iv = iv;
	cdm_in.iv_size = 16; //Always 16, see AP4_CencSingleSampleDecrypter declaration.
	cdm_in.key_id = wv_adapter->GetKeyId();
	cdm_in.key_id_size = wv_adapter->GetKeyIdSize();
	cdm_in.num_subsamples = subsample_count;
	cdm_in.subsamples = subsample_buffer_;

	CdmBuffer buf(&data_out);
	CdmDecryptedBlock cdm_out;
	cdm_out.SetDecryptedBuffer(&buf);

	cdm::Status ret = wv_adapter->Decrypt(cdm_in, &cdm_out);
	return AP4_SUCCESS;
	
}

/*******************************************************
					Bento4 Streams
					********************************************************/

class AP4_DASHStream : public AP4_ByteStream
{
public:
	// Constructor
	AP4_DASHStream(dash::DASHStream *dashStream) :dash_stream_(dashStream){};

	// AP4_ByteStream methods
	AP4_Result ReadPartial(void*    buffer,
		AP4_Size  bytesToRead,
		AP4_Size& bytesRead) override
	{
		bytesRead = dash_stream_->read(buffer, bytesToRead);
		return bytesRead > 0 ? AP4_SUCCESS : AP4_ERROR_READ_FAILED;
	};
	AP4_Result WritePartial(const void* buffer,
		AP4_Size    bytesToWrite,
		AP4_Size&   bytesWritten) override
	{
		/* unimplemented */
		return AP4_ERROR_NOT_SUPPORTED;
	};
	AP4_Result Seek(AP4_Position position) override
	{
		return dash_stream_->seek(position) ? AP4_SUCCESS : AP4_ERROR_NOT_SUPPORTED;
	};
	AP4_Result Tell(AP4_Position& position) override
	{
		position = dash_stream_->tell();
		return AP4_SUCCESS;
	};
	AP4_Result GetSize(AP4_LargeSize& size) override
	{
		/* unimplemented */
		return AP4_ERROR_NOT_SUPPORTED;
	};
	// AP4_Referenceable methods
	void AddReference() override {};
	void Release()override      {};
protected:
	// members
	dash::DASHStream *dash_stream_;
};

class AP4_SockStream : public AP4_ByteStream
{
public:
	// Constructor
	AP4_SockStream(int socket, AP4_Position offset) :socket_(socket), send_offset_(offset), position_(0), buffer_start_(~0){};

	// AP4_ByteStream methods
	AP4_Result ReadPartial(void*    buffer,
		AP4_Size  bytesToRead,
		AP4_Size& bytesRead) override
	{
		/* unimplemented */
		return AP4_ERROR_NOT_SUPPORTED;
	};
	AP4_Result WritePartial(const void* buffer,
		AP4_Size    bytesToWrite,
		AP4_Size&   bytesWritten) override
	{
		if (~buffer_start_)
		{
			AP4_Position rel = position_ - buffer_start_;
			if (rel + bytesToWrite > buffer_.size())
				buffer_.resize(static_cast<size_t>(rel + bytesToWrite));
			memcpy(&buffer_[static_cast<size_t>(rel)], buffer, bytesToWrite);
			bytesWritten = bytesToWrite;
			position_ += static_cast<AP4_Size>(bytesWritten);
			return AP4_SUCCESS;
		}
		int nWritten(0);
		bytesWritten = 0;
		const char *b(static_cast<const char *>(buffer));
		if (position_ < send_offset_)
		{
			if (position_ + bytesToWrite < send_offset_)
				return AP4_SUCCESS;
			bytesWritten = static_cast<AP4_Size>(send_offset_ - position_);
			bytesToWrite -= bytesWritten;
			b += bytesWritten;
		}
		while (bytesToWrite && (nWritten = send(socket_, b, bytesToWrite, MSG_NOSIGNAL)) != SOCKET_ERROR)
		{
			bytesToWrite -= nWritten;
			b += nWritten;
			bytesWritten += nWritten;
		}
		position_ += static_cast<AP4_Size>(bytesWritten);

		return (nWritten != SOCKET_ERROR) ? AP4_SUCCESS : AP4_ERROR_WRITE_FAILED;
	};
	AP4_Result Seek(AP4_Position position) override
	{
		if (~buffer_start_ && position >= buffer_start_)
		{
			if (position > buffer_start_ + buffer_.size())
				buffer_.resize(static_cast<std::string::size_type>(position - buffer_start_));
			position_ = position;
			return AP4_SUCCESS;
		}
		return AP4_ERROR_WRITE_FAILED;
	};
	AP4_Result Tell(AP4_Position& position) override
	{
		position = position_;
		return AP4_SUCCESS;
	};
	AP4_Result GetSize(AP4_LargeSize& size) override
	{
		/* unimplemented */
		return AP4_ERROR_NOT_SUPPORTED;
	};
	AP4_Result Buffer()
	{
		buffer_start_ = position_;
		buffer_.clear();
		return AP4_SUCCESS;
	}
	AP4_Result Flush()
	{
		buffer_start_ = ~0;
		position_ -= buffer_.size();
		AP4_Result result = Write(&buffer_[0], buffer_.size());
		if (AP4_SUCCEEDED(result) && GetObserver())
			return GetObserver()->OnFlush(this);
		return result;
	}
	// AP4_Referenceable methods
	void AddReference() override {};
	void Release()override      {};
protected:
	// members
	int socket_;
	AP4_Position position_;
	AP4_Position buffer_start_;
	AP4_Position send_offset_;
	std::vector<uint8_t> buffer_;
};

/*******************************************************
Main class Session
********************************************************/
class Session : public dash::DASHStreamObserver, public AP4_ByteStreamObserver, public media::CdmAdapterClient
{
public:
	Session(uint32_t session_id, const char *mpdURL, const char *licenseURL);
	Session(uint32_t session_id, const char *encoded);
	~Session();
	uint32_t GetSessionId(){ return session_id_; };
	bool setup_widevine(const uint8_t *init_data, const unsigned int init_data_size);
	bool initialize();
	void SetStreamProperties(uint16_t width, uint16_t height, const char* language, uint32_t maxBitPS, bool allow_ec_3);
	bool play(int socket_desc = 0, AP4_Position byteOffset = 0);
	void stop();
	//Override from dash::DASHStreamObserver
	void OnStreamChange(dash::DASHStream *stream, uint32_t segment)override;
	//Override from AP4SocketStreamObserver
	AP4_Result OnFlush(AP4_ByteStream *stream)override;
	virtual void OnCDMMessage(media::CdmAdapterClient::CDMADPMSG msg) override
	  {
		std::cout << "OnCDMMessage: " << msg << " " << std::endl;
		messages_.push_back(msg);
	  };
private:
	void thread_play(AP4_Position byteOffset);

	uint32_t session_id_;
	uint64_t session_expiation_;

	std::string wvLicenseURL_;
	std::string mpdFileURL_;
	std::string pssh_, license_url_;
	dash::DASHTree dashtree_;
	dash::DASHStream video_, audio_;
	bool SendSessionMessage();
	media::CdmAdapter *wvadapter_;
	AP4_ByteStream *video_input_, *audio_input_;
	std::deque<media::CdmAdapterClient::CDMADPMSG> messages_;
	uint16_t width_, height_;
	std::string language_;
	uint32_t fixed_bandwidth_;

	AP4_ProtectionKeyMap key_map_;
	AP4_Processor *processor_;
	AP4_UI16 key_size_;
	const AP4_UI08 *key_;
	uint32_t current_segment_[dash::DASHTree::STREAM_TYPE_COUNT];
	bool stream_changed_;
	std::thread *thread_;
	int socket_desc_;

};

Session::Session(uint32_t session_id, const char *mpdURL, const char *licenseURL)
	: session_id_(session_id)
	, session_expiation_(media::gtc() + 600000)
	, wvLicenseURL_(licenseURL)
	, mpdFileURL_(mpdURL)
	, width_(3840)
	, height_(2160)
	, language_("en")
	, fixed_bandwidth_(150000000)
	, video_(dashtree_, dash::DASHTree::VIDEO)
	, audio_(dashtree_, dash::DASHTree::AUDIO)
	, wvadapter_(NULL)
	, video_input_(NULL)
	, audio_input_(NULL)
	, processor_(NULL)
	, stream_changed_(false)
#ifdef SEPARATE_STREAMS
	, video_output(NULL)
	, audio_output(NULL)
#elif MUXED_STREAM
	, muxed_output_(NULL)
#else
	, thread_(NULL)
	, socket_desc_(0)
#endif
{
	video_.set_observer(this);
	audio_.set_observer(this);
	// create a key map object to hold keys
	key_map_.SetKey(1, reinterpret_cast<const AP4_UI08 *>("WIDEVINE"), 8); //Add a dummy key for track 1 (audio)
	key_map_.SetKey(2, reinterpret_cast<const AP4_UI08 *>("WIDEVINE"), 8); //Add a dummy key for track 2 (video)
}

Session::Session(uint32_t session_id, const char *encoded)
	:Session(session_id, "", "")
{
	const char *strGETEnd(strstr(encoded, " HTTP"));
	if (!strGETEnd)
		return;

	const char *strF(strstr(encoded, "mpdurl=")), *strE(strF ? strchr(strF, '&') : 0);
	uint8_t buffer[4096];

	if (!strE) strE = strGETEnd;
	if (strF && strE)
	{
		unsigned int newLen(4096);
		if (b64_decode(strF + 7, strE - strF - 7, buffer, newLen))
			mpdFileURL_ = std::string((const char*)buffer, newLen);
	}
	strF = strstr(encoded, "licurl=");
	strE = strF ? strchr(strF, '&') : 0;
	if (!strE) strE = strGETEnd;
	if (strF && strE)
	{
		unsigned int newLen(4096);
		if (b64_decode(strF + 7, strE - strF - 7, buffer, newLen))
			wvLicenseURL_ = std::string((const char*)buffer, newLen);
			
			
	}
}

Session::~Session()
{
	stop();

	delete wvadapter_;
	wvadapter_ = 0;
}

/*----------------------------------------------------------------------
|   curl callback
+---------------------------------------------------------------------*/

static size_t write_license(void *buffer, size_t size, size_t nmemb, void *dest)
{
	std::string *str(reinterpret_cast<std::string*>(dest));
	*str += std::string(reinterpret_cast<char*>(buffer), size*nmemb);
	return size*nmemb;
}

/*----------------------------------------------------------------------
| setup_widevine
+ -------------------------------------------------------------------- - */

bool Session::setup_widevine(const uint8_t *init_data, const unsigned int init_data_size)
{

	wvadapter_ = new media::CdmAdapter("com.widevine.alpha", widevinedll, "", media::CdmConfig(false, true),*(dynamic_cast<media::CdmAdapterClient*>(this)));
	std::cout << "wvAdapter init: " << widevinedll << " " << std::endl;
	std::cout << "wvAdapter init init_data: " << init_data << " " << std::endl;
	std::cout << "wvAdapter init init_data_size: " << init_data_size << " " << std::endl;
	if (!wvadapter_->valid())
	{
		std::cout << "ERROR: Unable to load widevine shared library" << std::endl;
		return false;
	}
	
	if (init_data_size > 256)
	{
		std::cout << "ERROR: init_data with length: " << init_data_size << " seems not to be cenc init data!" << std::endl;
		return false;
	}
	std::cout << "wvAdapter init Done!" << std::endl;
	// This will request a new session and initializes session_id and message members in cdm_adapter.
	// message will be used to create a license request in the step after CreateSession call.
	// Initialization data is the widevine cdm pssh code in google proto style found in mpd schemeIdUri
	unsigned int buf_size = 32 + init_data_size;
	std::cout << "wvAdapter init buf_size: " << buf_size << " " << std::endl;
	uint8_t buf[1024];
	static uint8_t proto[] = { 0x00, 0x00, 0x00, 0x63, 0x70, 0x73, 0x73, 0x68, 0x00, 0x00, 0x00, 0x00, 0xed, 0xef, 0x8b, 0xa9,
    0x79, 0xd6, 0x4a, 0xce, 0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed, 0x00, 0x00, 0x00, 0x00 };
	proto[3] = static_cast<uint8_t>(buf_size);
	proto[31] = static_cast<uint8_t>(init_data_size);
	std::cout << "wvAdapter init sizeof(proto): " << sizeof(proto) << " " << std::endl;
	std::cout << "wvAdapter init proto: " << proto << " " << std::endl;
	memcpy(buf, proto, sizeof(proto));
	memcpy(&buf[32], init_data, init_data_size);
	std::cout << "wvAdapter init buf_size: " << buf << " " << std::endl;
	wvadapter_->CreateSessionAndGenerateRequest(0, cdm::SessionType::kTemporary, cdm::InitDataType::kCenc, buf, buf_size);
	
	if (wvadapter_->SessionValid())
	{
		std::string license, challenge(b64_encode(wvadapter_->GetMessage(), wvadapter_->GetMessageSize(), true));
		
		challenge = "widevine2Challenge=" + challenge;
		challenge += "&includeHdcpTestKeyInLicense=true";
		std::cout << "License: " << license  << std::endl;
		std::cout << "Challenge: " << challenge  << std::endl;
		static const unsigned int numDefaultHeaders(6);
		static const char* licHeaders[numDefaultHeaders] = {
			"Accept: application/json",
			"Pragma: no-cache",
			"Cache-Control: no-cache",
			"Content-Type: application/x-www-form-urlencoded",
			"Accept-Encoding: gzip, deflate",
			"expect:"
		};

		// Get the license
		curl_global_init(CURL_GLOBAL_ALL);

		struct curl_slist *headerlist = NULL;
		for (unsigned int i(0); i < numDefaultHeaders; ++i)
			headerlist = curl_slist_append(headerlist, licHeaders[i]);
		std::cout << "wvLicenseURL_: " << wvLicenseURL_.c_str() << " " << std::endl;
		CURL *curl = curl_easy_init();
		curl_easy_setopt(curl, CURLOPT_URL, wvLicenseURL_.c_str());
		curl_easy_setopt(curl, CURLOPT_POST, 1L);

		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
		/* Set the form info */
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, challenge.c_str());
		/* Define our callback to get called when there's data to be written */
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_license);
		/* Set a pointer to our struct to pass to the callback */
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &license);
		/* Disable security checks here */
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		/* Automaticlly decompress gzipped responses */
		curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "gzip");
		CURLcode res = curl_easy_perform(curl);
		
		if (res != CURLE_OK)
		{
			stop();
			std::cout << "ERROR: curl - license request failed (" << license << ")" << std::endl;
			return false;
		}

		std::string::size_type licStartPos(license.find("\"license\":\""));
		if (licStartPos == std::string::npos)
		{
			stop();
			std::cout << "ERROR: license start position not found (" << license << ")" << std::endl;
			return false;

		}
		licStartPos += 11;
		std::string::size_type licEndPos(license.find("\",", licStartPos));
		if (licEndPos == std::string::npos)
		{
			stop();
			std::cout << "ERROR: license end position not found (" << license << ")" << std::endl;
			return false;
		}

		buf_size = 1024;
		b64_decode(license.c_str() + licStartPos, licEndPos - licStartPos, buf, buf_size);
		wvadapter_->UpdateSession(buf, buf_size);
		
		std::cout << "INFO: License received:" << license.c_str() << std::endl;
		std::cout << "INFO: licStartPos:" << licStartPos << std::endl;
		std::cout << "INFO: licEndPos:" << licEndPos << std::endl;
		std::cout << "INFO: License decoded:" << buf << std::endl;
		if (!wvadapter_->KeyIdValid())
		{
			stop();
			std::cout << "INFO: License update not successful" << std::endl;
			return false;
		}
		return true;
		if (!wvadapter_->KeyIdValid())
		{
			stop();
			std::cout << "INFO: License update not successful" << std::endl;
			return false;
		}
		return true;
	}
	else
		std::cout << "ERROR: WV sessionrequest invalid!" << std::endl;
	return false;
		std::cout << "ERROR: WV sessionrequest invalid!" << std::endl;
	return false;
}

/*----------------------------------------------------------------------
|   initialize
+---------------------------------------------------------------------*/

bool Session::initialize()
{
	stop();

	const char* delim(strrchr(mpdFileURL_.c_str(), '/'));
	if (!delim)
	{
		std::cout << "ERROR: Invalid mpdURL: / expected (" << mpdFileURL_ << ")" << std::endl;
		return false;
	}
	dashtree_.base_url_ = std::string(mpdFileURL_.c_str(), (delim - mpdFileURL_.c_str()) + 1);

	if (!dashtree_.open(mpdFileURL_.c_str()) || !dashtree_.has_type(dash::DASHTree::VIDEO) || !dashtree_.has_type(dash::DASHTree::AUDIO))
	{
		std::cout << "ERROR: Could not open / parse mpdURL (" << mpdFileURL_ << ")" << std::endl;
		return false;
	}
	std::cout << "mpdURL (" << mpdFileURL_ << ")" << std::endl;
	std::cout << "Info: Successfully parsed .mpd file. Download speed: " << dashtree_.download_speed_ << "Bytes/s" << std::endl;

	if (dashtree_.pssh_.empty() || dashtree_.pssh_ == "FILE")
		return true;

	//We can use pssh data from mpd

	// This will request a new session and initializes session_id and message members in cdm_adapter.
	// message will be used to create a license request in the step after CreateSession call.
	// Initialization data is the widevine cdm pssh code in google proto style found in mpd schemeIdUri
	uint8_t init_data[256];
	unsigned int init_data_size(256);

	b64_decode(dashtree_.pssh_.data(), dashtree_.pssh_.size(), init_data, init_data_size);

	return  setup_widevine(init_data, init_data_size);
}

void Session::thread_play(AP4_Position byteOffset)
{
#if !defined(SEPARATE_STREAMS) && !defined(MUXED_STREAM)
	std::cout << "INFO: thread for session-id: " << session_id_ << " started" << std::endl;
	AP4_SockStream sock_output(socket_desc_, byteOffset);
	sock_output.SetObserver(dynamic_cast<AP4_ByteStreamObserver*>(this));
	std::string ret("HTTP/1.1 200 OK\r\nContent-Type: video/mp4\r\n\r\n");
	send(socket_desc_, ret.c_str(), ret.size(), 0);
	AP4_Array<AP4_ByteStream*> streams;
	streams.SetItemCount(2);
	streams[0] = audio_input_;
	streams[1] = video_input_;

	AP4_Result result = AP4_ERROR_INVALID_FORMAT;
	do {
		if (AP4_SUCCEEDED(processor_->Mux(streams, sock_output, 1, NULL)))
		{
			//Skip to the first MOOF Segments
			audio_.start_stream(current_segment_[dash::DASHTree::AUDIO]);
			video_.start_stream(current_segment_[dash::DASHTree::VIDEO]);
			result = processor_->Mux(streams, sock_output, 2, NULL);
			std::cout << "INFO: playing: " << session_id_ << "" << std::endl;
		}
	} while (result == AP4_ERROR_STREAM_CHANGED);

	audio_.clear();
	video_.clear();

	closesocket(socket_desc_);
	socket_desc_ = 0;
	std::cout << "INFO: thread for session-id: " << session_id_ << " terminated" << std::endl;

	// Send the server a message that we are ready
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in serv_addr;
	struct hostent *server;

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(8888);
	server = gethostbyname("127.0.0.1");
	memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);

	if (connect(sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) == 0)
	{
		char buf[128];
		sprintf(buf, "GET /close?%d HTTP/1.0\r\n\r\n", session_id_);
		send(sock, buf, strlen(buf), 0);
		closesocket(sock);
	}
#endif
}


bool Session::play(int socket_desc, AP4_Position byteOffset)
{
	stop();
	std::cout << "Start Playing" << std::endl;
	if (!video_.prepare_stream(width_, height_, 0, fixed_bandwidth_))
	{
		std::cout << "ERROR: Could not prepare video stream" << std::endl;
		return false;
	}
	video_input_ = new AP4_DASHStream(&video_);
	
	//if no pssh data was in .mpd file but we have encrypted data, take it from video file
	if (!wvadapter_ && dashtree_.pssh_ == "FILE")
	{
		AP4_File input(*video_input_, AP4_DefaultAtomFactory::Instance, true);
		AP4_Movie* movie = input.GetMovie();
		if (!movie)
		{
			std::cout << "ERROR: Could not extract license from video stream (MOOV not found)" << std::endl;
			return false;
		}
		AP4_Array<AP4_PsshAtom*>& pssh = movie->GetPsshAtoms();

		unsigned char key_system[16];
		AP4_ParseHex("edef8ba979d64acea3c827dcd51d21ed", key_system, 16);

		std::string license;
		for (unsigned int i = 0; license.empty() && i < pssh.ItemCount(); i++)
			if (memcmp(pssh[i]->GetSystemId(), key_system, 16) == 0)
				license = std::string((const char *)pssh[i]->GetData().GetData(), pssh[i]->GetData().GetDataSize());
		if (license.empty())
		{
			std::cout << "ERROR: Could not extract license from video stream (PSSH not found)" << std::endl;
			return false;
		}
		if (!setup_widevine((const uint8_t*)license.data(), license.size()))
			return false;
		video_input_->Seek(0);
		std::cout << "video_input_->Seek(0);" << std::endl;
	}

	if (!audio_.prepare_stream(0, 0, language_.c_str(), fixed_bandwidth_))
	{
		std::cout << "ERROR: Could not prepare audio stream" << std::endl;
		return false;
	}
	audio_input_ = new AP4_DASHStream(&audio_);

#ifdef SEPARATE_STREAMS
	std::cout << "SEPARATE_STREAMS" << std::endl;
	AP4_FileByteStream::Create("C:\\Temp\\video.mov", AP4_FileByteStream::STREAM_MODE_WRITE, video_output_);
	AP4_FileByteStream::Create("C:\\Temp\\audio.mov", AP4_FileByteStream::STREAM_MODE_WRITE, audio_output_);
#elif MUXED_STREAM
	std::cout << "MUXED_STREAM" << std::endl;
	AP4_FileByteStream::Create("/tmp/muxed.mov", AP4_FileByteStream::STREAM_MODE_WRITE, muxed_output_);
	muxed_output_->SetObserver(this);
#endif

	processor_ = new AP4_CencDecryptingProcessor(&key_map_, NULL, new WV_CencSingleSampleDecrypter(wvadapter_));

	AP4_Result result;
#ifdef SEPARATE_STREAMS
	result = processor_->Process(*audio_input_, *audio_output_, NULL);
	result = processor_->Process(*video_input_, *video_output_, NULL);
#elif MUXED_STREAM
	AP4_Array<AP4_ByteStream*> streams;
	streams.SetItemCount(2);
	streams[0] = audio_input_;
	streams[1] = video_input_;

	do {
		if (AP4_SUCCEEDED(result = processor_->Mux(streams, *muxed_output_, 1, NULL)))
		{
			//Skip to the first MOOF Segments
			audio_.start_stream(current_segment_[dash::DASHTree::AUDIO]);
			video_.start_stream(current_segment_[dash::DASHTree::VIDEO]);
			result = processor_->Mux(streams, *muxed_output_, 2, NULL);
		}
	} while (result == AP4_ERROR_STREAM_CHANGED);

	video_.set_bandwidth(1);
	video_.select_stream(true);
	audio_.select_stream(true);
	processor_->Mux(streams, *muxed_output_, 1, NULL);
	audio_.start_stream(current_segment_[dash::DASHTree::AUDIO]);
	video_.start_stream(current_segment_[dash::DASHTree::VIDEO]);
	result = processor_->Mux(streams, *muxed_output_, 2, NULL);

#else
	socket_desc_ = socket_desc;
	thread_ = new std::thread(&Session::thread_play, this, byteOffset);
	std::cout << "direct play" << std::endl;
	return true;
#endif
	return result == AP4_SUCCESS;
}

void Session::stop()
{
	video_.stop();
	audio_.stop();

#if !defined SEPARATE_STREAMS && !defined(MUXED_STREAM)
	shutdown(socket_desc_, 2);
	if (thread_) {
		if (thread_->joinable())
			thread_->join();
		delete thread_;
		thread_ = NULL;
	}
#endif

	delete video_input_;
	video_input_ = 0;

	delete audio_input_;
	audio_input_ = 0;

#ifdef SEPARATE_STREAMS
	delete audio_output_;
	audio_output_ = 0;

	delete video_output_;
	video_output_ = 0;
#elif MUXED_STREAM
	delete muxed_output_;
	muxed_output_ = 0;
#endif
	memset(current_segment_, 0, sizeof(current_segment_));
}

void Session::OnStreamChange(dash::DASHStream *stream, uint32_t segment)
{
	std::cout << "Info: ";
	stream->info(std::cout);
	std::cout << "last segment:" << segment << std::endl;
	current_segment_[stream->get_type()] = segment;
}

AP4_Result Session::OnFlush(AP4_ByteStream *stream)
{
	/* OnFlush is called after each MP4 MOOF atom (= stream segment)
		 Because it is called before next segment is accessed, Its a good place to handle stream changes
		 - call DASHStream::select_stream(noforce) for each stream
		 - DASHStream::select_stream will call this->OnStreamChange() wich stores the current segment
		 - if there was a change -> call DASHStream::select_stream(force) to prepare every stream
		 - if Mux(2) returns EOS and we have changes we will continue in thread_play
		 */
	std::cout << "OnFlush: ";
#if MUXED_STREAM
	static uint32_t counter(0);
	if (++counter == 10)
	{
		//counter = 0;
		return AP4_ERROR_EOS;
	}
#endif
	return AP4_SUCCESS;
}

#if !defined SEPARATE_STREAMS && !defined MUXED_STREAM 

int main(int argc, char *argv[])
{
	int socket_desc, client_sock;
	socklen_t c;
	struct sockaddr_in server, client;
	std::string strMessage;
	uint32_t sessionId(0);
	std::vector<Session*> session_stack;

	if (!WSASU())
		return -1;

	//Create socket
	socket_desc = socket(AF_INET, SOCK_STREAM, 0);
	if (socket_desc == -1)
	{
		std::cout << "FATAL: Could not create socket" << std::endl;
		return -1;
	}

	//Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(8888);

	//Bind
	if (bind(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0)
	{
		//print the error message
		std::cout << "FATAL: bind failed.Error" << std::endl;
		return -1;
	}

	//Listen
	listen(socket_desc, 3);

	//Accept and incoming connection
	std::cout << "INFO: Waiting for incoming connections..." << std::endl;
	c = sizeof(struct sockaddr_in);

	while ((client_sock = accept(socket_desc, (struct sockaddr *)&client, &c)))
	{
		//Receive a message from client
		char read_buf[1024];
		int read_size;
		strMessage.clear();
		while ((read_size = recv(client_sock, read_buf, 1024, 0)) > 0)
		{
			strMessage += std::string(read_buf, read_size);
			std::string::size_type endGet;

			if ((endGet = strMessage.find("\r\n\r\n")) != std::string::npos)
			{
				strMessage.resize(endGet);
				break;
			}
		}
		if (read_size >= 0)
		{
			if (strncmp(strMessage.c_str(), "GET /initialize?", 16) == 0)
			{
				Session *session = new Session(++sessionId, strMessage.c_str() + 16);
				if (session->initialize())
				{
					std::cout << "INFO: new session created: " << sessionId << std::endl;
					session_stack.push_back(session);
					std::stringstream cmd;
					cmd << "HTTP/1.1 200 OK\r\nSession-Id: " << sessionId << "\r\n\r\n";
					send(client_sock, cmd.str().c_str(), cmd.str().size(), 0);
					closesocket(client_sock);
				}
				else {
					delete session;
					std::cout << "ERROR: Unable to create / initialize session!" << std::endl;
				}
			}
			else if (strncmp(strMessage.c_str(), "GET /play?", 10) == 0)
			{
				uint32_t sid = atoi(strMessage.c_str() + 10);
				std::vector<Session*>::iterator b(session_stack.begin()), e(session_stack.end());
				for (; b != e; ++b)
					if ((*b)->GetSessionId() == sid)
						break;
				if (b != e)
				{
					if (!(*b)->play(client_sock, 0))
					{
						std::cout << "ERROR: Unable to play stream with session_id: " << sid << " <- removed!" << std::endl;
						delete (*b);
						session_stack.erase(b);
					}
					else
					{
						std::cout << "INFO: Start playing stream with session_id: " << sid << std::endl;
						goto success;
					}
				}
				else
					std::cout << "ERROR: Unable to find stream with session_id: " << sid << std::endl;
			}
			else if (strncmp(strMessage.c_str(), "GET /shutdown?", 14) == 0)
			{
			
			}
			else if (strncmp(strMessage.c_str(), "GET /close?", 11) == 0)
			{
				uint32_t sid = atoi(strMessage.c_str() + 11);
				std::vector<Session*>::iterator b(session_stack.begin()), e(session_stack.end());
				for (; b != e; ++b)
					if ((*b)->GetSessionId() == sid)
						break;
				if (b != e)
				{
					std::cout << "INFO: Removing session with session_id: " << sid << std::endl;
					delete (*b);
					session_stack.erase(b);
				}
			}
			else if (strncmp(strMessage.c_str(), "HEAD", 4) != 0)
			{
				std::cout << "ERROR: Unknown command: " << strMessage << std::endl;
			}
			else
			{
				strMessage = "HTTP/1.1 200 OK\r\nContent-Type: video/quicktime\r\n\r\n";
				send(client_sock, strMessage.c_str(), strMessage.size(), 0);
				closesocket(client_sock);
				goto success;
			}
			strMessage = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
			send(client_sock, strMessage.c_str(), strMessage.size(), 0);
		}
		closesocket(client_sock);
	success:;
	}

	for (std::vector<Session*>::iterator b(session_stack.begin()), e(session_stack.end()); b != e; ++b)
		delete *b;

	if (client_sock < 0)
	{
		std::cout << "FATAL: accept failed." << std::endl;
		return -1;
	}
	WSACU();
	return 0;
}
#else
int main()
{
	//const char *lic = "TBD";
	//const char *mpd = "TBD";

	Session s(0, mpd, lic);
	//s.SetStreamProperties(,,,,,,); //use defaults
	if (s.initialize())
		s.play();

	return 0;
}
#endif
