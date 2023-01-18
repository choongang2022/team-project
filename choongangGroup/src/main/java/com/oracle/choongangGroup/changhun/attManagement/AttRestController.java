package com.oracle.choongangGroup.changhun.attManagement;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.servlet.http.HttpSession;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.oracle.choongangGroup.changhun.JPA.Member;
import com.oracle.choongangGroup.changhun.JPA.Work;
import com.oracle.choongangGroup.changhun.address.MemberRepository;
import com.oracle.choongangGroup.dongho.auth.authutils.GetMember;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequiredArgsConstructor
@Slf4j
public class AttRestController {
	
	private final AttManagementRepository repository;
	private final AttManagementService service;
	private final MemberRepository memRepository;
	private final GetMember getMember;
	
	@RequestMapping(value = "attInsert")
	public String attInsert() {
		String msg = null;
		
		try {
			msg = service.attInsert();
		} catch (Exception e) {
			System.out.println("=============================================");
			System.out.println("AttManagementService attInsert 오류발생" + e.getMessage());
			System.out.println("=============================================");
		}
		
		System.out.println(msg);
		
		return msg;
	}
	
	@RequestMapping(value = "attOff")
	public String attOff() {
		String msg = null;
		
		try {
			service.attOff();
		} catch (Exception e) {
			System.out.println("attOff 오류-->" + e.getMessage());
			msg = "이미 출근 등록이 되었습니다!";
		}
		
		System.out.println(msg);
		
		return msg;
	}
	
	@PostMapping(value = "/attClk")
	public List<Work> attMyFormClk(@RequestParam(required = false, defaultValue = "0", value="page")int page) {
		
		System.out.println("page --> " + page);
//		String userid = (String) session.getAttribute("userid");
		Member member = getMember.getMember();
		String userid = member.getUserid();
		
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM");
		Date now = new Date();
		String nowDate = sdf.format(now);
		Page<Work> workList = repository.findPageByMember_UseridAndWorkDateContaining(userid,nowDate,PageRequest.of(page, 5, Sort.by(Sort.Direction.ASC,"workDate")));
		List<String> list = new ArrayList<String>();
		list.add("가자");
		
		return workList.getContent();
	}
	
	@RequestMapping(value = "/memberAttList")
	public List<Work> memberAttList(@RequestParam(value = "name") String name,
									@RequestParam(value = "month") String month) {

		List<Work> workUserlist = repository.findByMember_nameAndWorkDateContaining(name, month);
		
		log.info("workUserlist --> {}",workUserlist.size());
		
		return workUserlist;
	}
	
	@RequestMapping(value = "/updateMemAtt")
	public void updateMemAtt(@RequestParam(value = "attOntime") String attOntime,
							 @RequestParam(value = "attOfftime") String attOfftime,
							 @RequestParam(value = "vacation") long vacation,
							 @RequestParam(value = "userid") String userid,
							 @RequestParam(value = "workDate") String workDate) {
		
		System.out.println("attOntime --> " + attOntime);
		System.out.println("attOfftime --> " + attOfftime);
		System.out.println("vacation --> " + vacation);
		System.out.println("userid --> " + userid);
		System.out.println("workDate --> " + workDate);
		
		
		Member member = memRepository.findByUserid(userid);
		member.setVacation(vacation);
		memRepository.save(member);
		
		service.updateWork(attOntime,attOfftime,workDate,userid);
		
	}
	
	
}
