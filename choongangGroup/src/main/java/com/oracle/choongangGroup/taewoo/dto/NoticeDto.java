package com.oracle.choongangGroup.taewoo.dto;

import com.oracle.choongangGroup.taewoo.domain.BaseTimeEntity;
import com.oracle.choongangGroup.taewoo.domain.Notice;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class NoticeDto extends BaseTimeEntity {
	private Long noticeNum;
	private String writerUserid;
	private String noticeTitle;
	private String noticeContent;
	private String noticeType;
	
	public static NoticeDto toDto(Notice notice) {
		return new NoticeDto(
				notice.getNoticeNum(),
				notice.getNoticeTitle(),
				notice.getNoticeContent(),
				notice.getNoticeType(),
				notice.getWriter().getUserid()		
				);
	}
			
}
