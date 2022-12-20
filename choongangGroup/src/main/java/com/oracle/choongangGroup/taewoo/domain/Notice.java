package com.oracle.choongangGroup.taewoo.domain;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.SequenceGenerator;
import javax.persistence.Table;


import com.oracle.choongangGroup.changhun.JPA.Member;

import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@NoArgsConstructor
@SequenceGenerator(
					name = "NOTICE_SEQ_GEN",
					sequenceName = "NOTICE_SEQ_GENERATOR",
					initialValue = 1,
					allocationSize = 1
		
				)
@Table
public class Notice extends BaseTimeEntity {

		@Id
		@Column(name = "notice_num")
		@GeneratedValue(
						generator = "NOTICE_SEQ_GEN",
						strategy = GenerationType.SEQUENCE
					)
		private Long noticeNum;					// No.
		
		@ManyToOne(fetch = FetchType.LAZY)
		@JoinColumn(name = "userid")
		private Member writer;					// 작성자

		@Column(name = "notice_title")
		private String noticeTitle;				// 제목
		
		@Column(name = "notice_content" , length = 5000)
		private String noticeContent;			// 내용
		
		@Column(name = "notice_type")
		private String noticeType;				// 구분
				
		@Column(name = "notice_hit")
		private int noticeHit;					// 조회수
		
}
