package com.oracle.choongangGroup.taewoo.service;

import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;

import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.oracle.choongangGroup.changhun.JPA.Member;
import com.oracle.choongangGroup.changhun.address.MemberRepository;
import com.oracle.choongangGroup.taewoo.domain.Message;
import com.oracle.choongangGroup.taewoo.dto.MessageDto;
import com.oracle.choongangGroup.taewoo.repository.MessageRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
@Transactional
public class MessageService {
	private final MessageRepository messageRepository;
	private final MemberRepository memberRepository;
	
	// 쪽지 보내기
	public MessageDto write(MessageDto messageDto) {
		System.out.println("MessageService write start....");
		Member receiver = memberRepository.findByUserid(messageDto.getReceiverUserid());
		Member sender = memberRepository.findByUserid(messageDto.getSenderUserid());
		
		Message message = new Message();
		message.setReceiver(receiver);
		message.setSender(sender);
		message.setSenderName(messageDto.getSenderName());
		message.setMessageTitle(messageDto.getMessageTitle());
		message.setMessageContent(messageDto.getMessageContent());
		message.setDeletedByReceiver(false);
		message.setDeletedBySender(false);
		messageRepository.save(message);
		
		return MessageDto.toDto(message);
	}

	// 받은 쪽지함
	public List<MessageDto> receiveMessage(Member member, Pageable pageable) {
//		   List<Message> messages = messageRepository.findAllByReceiver(member);	
		   List<Message> messages = messageRepository.findByReceiverOrderByMessageIdDesc(member,  pageable);
	        List<MessageDto> messageDtos = new ArrayList<>();

	        for(Message message : messages) {
	            // message 에서 받은 편지함에서 삭제하지 않았으면 보낼 때 추가해서 보내줌
	            if(!message.isDeletedByReceiver()) {
	                messageDtos.add(MessageDto.toDto(message));
	            }
	        }
	        return messageDtos;
	}
	// 보낸 쪽지함
	public List<MessageDto> senderMessage(Member member, Pageable pageable) {
		 List<Message> messages = messageRepository.findBySenderOrderByMessageIdDesc(member, pageable);
	        List<MessageDto> messageDtos = new ArrayList<>();

	        for(Message message : messages) {
	            // message 에서 받은 편지함에서 삭제하지 않았으면 보낼 때 추가해서 보내줌
	            if(!message.isDeletedBySender()) {
	                messageDtos.add(MessageDto.toDto(message));
	            }
	        }
	        return messageDtos;
	}

	// 받은 쪽지 삭제
	public int delete(Long messageId, Member member) {
		Message message = messageRepository.findByMessageId(messageId);
		System.out.println("delete start....");
		System.out.println(messageId);
		System.out.println(message.isDeletedByReceiver());
		System.out.println(message.isDeleted());
		message.deletedByReceiver();		
		if(message.isDeleted()) {
			int result = messageRepository.deleteByMessageId(messageId);
			return result;
			}
			int result = messageRepository.updateDeleteReceiver(messageId);
			return result;
	}
	
	// 보낸 쪽지 삭제
	public int senderDelete(Long messageId, Member member) {
		Message message = messageRepository.findByMessageId(messageId);
		System.out.println("senderDelete start....");
		System.out.println("messageId -->" + messageId);
		System.out.println(message.isDeletedBySender());
		System.out.println(message.isDeleted());
		message.deleteBySender();
		if(message.isDeleted()) {
			int result = messageRepository.deleteByMessageId(messageId);
			return result;
		}
		int result = messageRepository.updateDeleteSender(messageId);
		return result;
	}


	// 상세 쪽지
	public Message Detail(Long messageId) {
		System.out.println("MessageService Detail start....");
		System.out.println("messageId -->" + messageId);
		Message message = messageRepository.findById(messageId).orElseThrow(() -> new NoSuchElementException());
		return message;
	}






	
	

}
