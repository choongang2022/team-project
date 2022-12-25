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

import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

import com.oracle.choongangGroup.changhun.JPA.Member;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@SequenceGenerator(
					name = "MESSAGE_SEQ_GENERATOR",
					sequenceName = "MESSAGE_SEQ_GEN",
					initialValue = 1,
					allocationSize = 1
					)
public class Message extends BaseTimeEntity {
	
	@Id
	@GeneratedValue(
					generator = "MESSAGE_SEQ_GENERATOR",
					strategy = GenerationType.SEQUENCE
			)
	private Long messageId;
	
	private String messageTitle;
	
	@Column(length = 50000)
	private String messageContent;
	
	private boolean deletedBySender;
	
	private boolean deletedByReceiver;
	
	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "sender_userid")
	@OnDelete(action = OnDeleteAction.NO_ACTION)
	private Member sender;
	
	private String senderName;
	
	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "receiver_userid")
	@OnDelete(action = OnDeleteAction.NO_ACTION)
	private Member receiver;
	
	public void deleteBySender() {
		this.deletedByReceiver = true;
	}
	
	public void deletedByReceiver() {
		this.deletedByReceiver = true;
		
	}
	
	public boolean isDeleted() {
		return isDeletedByReceiver() && isDeletedBySender();
	}
	

}
