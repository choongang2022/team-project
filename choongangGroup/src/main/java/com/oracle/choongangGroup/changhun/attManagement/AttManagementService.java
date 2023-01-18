package com.oracle.choongangGroup.changhun.attManagement;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.DayOfWeek;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.oracle.choongangGroup.changhun.JPA.Member;
import com.oracle.choongangGroup.changhun.JPA.Work;
import com.oracle.choongangGroup.changhun.JPA.WorkStatus;
import com.oracle.choongangGroup.changhun.address.MemberRepository;
import com.oracle.choongangGroup.dongho.auth.authutils.GetMember;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class AttManagementService {

	private final AttCustomRepository attCustomRepository;
	private final AttManagementRepository repository;
	private final MemberRepository memRepository;
	private final GetMember getMember;
	
	// 출근 등록
	public String attInsert() {
		
		Member member1 = getMember.getMember();
		String userid = member1.getUserid();
		Member member = memRepository.findByUserid(userid);
		
		SimpleDateFormat sdf1 = new SimpleDateFormat("HH:mm:ss");
		SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
		
		Date now = new Date();
		
		String nowTime = sdf1.format(now);
		String nowDate = sdf2.format(now);
		
		Work work =  new Work(member);
//		List<Work> worklist = repository.findByUseridAndWorkDate(userid,nowDate);
		List<Work> worklist = repository.findByMember_UseridAndWorkDate(userid,nowDate);
		log.info("attInsert worklist --> {}",worklist.size());
		
		if(worklist.size() == 0) {
			work.setUserid(userid);
//			work.setMember(member);
			log.info("attInsert work getmember -->  {} ", work.getMember().getUserid());
			work.setAttOnTime(nowTime);			
			work.setWorkDate(nowDate);
			
			int result = timeCompare(nowTime);
			
			if(result == 1) {
				work.setAttStatus(WorkStatus.지각);
			} else {
				work.setAttStatus(WorkStatus.출근);
			}
			
//			attCustomRepository.save(work);
			repository.save(work);
		}
		System.out.println(worklist.size());
		String msg = "출근등록이 완료되었습니다";
		if(worklist.size() == 1) {
			msg = "이미 출근등록이 되었습니다";
		}
		
		return msg;
			
		
	}
	
	
	// 9시이후이면 지각으로 처리
	public int timeCompare(String nowTime) {		
		int result = 0;
		String nowtimeReplace = nowTime.replaceAll(":", "");
		int nowtimeInt = Integer.parseInt(nowtimeReplace);
		if(nowtimeInt > 90000) {
			result = 1;
		}
		
		return result;
	}

	// 퇴근 등록
	public void attOff() throws ParseException {
		Member member1 = getMember.getMember();
		String userid = member1.getUserid();
		
		// 날짜 포맷
		SimpleDateFormat sdf1 = new SimpleDateFormat("HH:mm:ss");
		SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
		
		// 날짜 객체 생성
		Date now = new Date();
		
		String nowTime = sdf1.format(now);
		String nowDate = sdf2.format(now);
		
		List<Work> work = attCustomRepository.findAttOnDate(userid,nowDate);
		
		String findAttOntime = work.get(0).getAttOnTime();
		
		// 하루 총 근무시간 구하기
		String totalResult = timeMinus(nowTime, findAttOntime);
		
		System.out.println("totalResult1 --> " + totalResult);
		
		attCustomRepository.attOff(userid,nowDate,nowTime,totalResult);
		
		
		
		
		
		
//		// 함수 구현 테스트
//		int lastDay = getLastMonth("2022-04-21");
//		System.out.println("lastNum -> " + lastDay);
//		// 무슨 요일인지
//		int whatDay = whatDay("2022-04-21");
//		System.out.println("whatDay --> " + whatDay);
//		// 날짜 세팅 값
//		int setDate = setDate(whatDay);
//		System.out.println("setDate --> " + setDate);
//		// 최종 몇주차까지 있는지?
//		int result = howManyWeek(lastDay, whatDay, setDate);
//		System.out.println(result);
	}
	
	// 시간 차 구하기
	public String timeMinus(String mainTime, String subTime) throws ParseException {
		int mainHour = Integer.parseInt(mainTime.substring(0,2));
		int subHour = Integer.parseInt(subTime.substring(0,2));
		
		SimpleDateFormat sdf1 = new SimpleDateFormat("HH:mm:ss");
		// 문자열 -> Date
		Date sub  = sdf1.parse(subTime);
		System.out.println("main -->" + mainTime);
		Date main = sdf1.parse(mainTime);
		System.out.println("sub -->" + subTime);
		System.out.println();
		
		//비교
		long hour, min,sec = 0;
		hour = mainHour - subHour;
		System.out.println("hour --> " + hour);
		if(main.getMinutes()<sub.getMinutes()) {
			min 	= (60+main.getMinutes()) - sub.getMinutes();
			hour -= 1;
		} else {
			min 	= main.getMinutes() - sub.getMinutes();			
		}
		
		if(main.getSeconds()<sub.getSeconds()) {
			sec 	= (60+main.getSeconds()) - sub.getSeconds();
			min -= 1;
		} else {
			sec 	= main.getSeconds() - sub.getSeconds();			
		}
		
		System.out.println("Hour->" + (hour));
		System.out.println("Min->" + min);
		System.out.println("sec->" + sec);
		
		
		String totalResult = String.format("%02d:%02d:%02d", hour,min,sec);
		
		return totalResult;
	}
	
	
	// 현재 날짜 구하기
	public String today() {
		
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
		Date now = new Date();
		String nowDate = sdf.format(now);
		
		return nowDate;
	}
	
	// 날짜 더하기
	public String addDate(String today, int year, int month, int day) throws ParseException {
		
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
		
		Calendar cal = Calendar.getInstance();
		
		Date dt = sdf.parse(today);
		
		cal.setTime(dt);
		
		cal.add(Calendar.YEAR, year);
		cal.add(Calendar.MONTH, month);
		cal.add(Calendar.DATE, day);
		
		return sdf.format(cal.getTime());
	}
	
//	 현재 날짜 무슨 요일인지 구하기
	public int whatDay(String yyyyMMdd) {
		
		String date = yyyyMMdd.replace("-","");
		int year  = Integer.parseInt(date.substring(0,4));
		int month = Integer.parseInt(date.substring(4,6));
		int day = Integer.parseInt(date.substring(6,8));
		
		LocalDate localdate = LocalDate.of(year, month, day);
		
		DayOfWeek dayOfWeek = localdate.getDayOfWeek();
		
		int dayOfDay = dayOfWeek.getValue();
		
		return dayOfDay;
	}
	
	// 마지막 날짜 구하기
	public int getLastMonth(String yyyyMMdd) {
		
		String date = yyyyMMdd.replace("-","");
		String year  = date.substring(0,4);
		String month = date.substring(4,6);
		
		Calendar cal = Calendar.getInstance();
		cal.set(Integer.parseInt(year), Integer.parseInt(month)-1,1);
		
		int lastDay = cal.getActualMaximum(Calendar.DAY_OF_MONTH);
		
		return lastDay;
	}
	

	
	// 달의 시작 날짜로 세팅값 변경
	public String setDate(String today) {
		
		String todayStr = today.replace("-", "");
		String year = todayStr.substring(0,4);
		String month = todayStr.substring(4,6);
		
		return String.format("%s-%s-01", year,month);
		
	}
	
//	// 몇주차까지 있는 확인
//	public int howManyWeek(int lastDay,int dayOfDay, int setDate) {
//		
//		int weekCount = 0;
//		int checkRemain = 0;
//		
//		System.out.println("dayOfDay --> " + dayOfDay);
//		
//		weekCount 	= (lastDay-setDate+1)/7;
//		System.out.println("weekCount --> " + weekCount);
//		checkRemain = (lastDay-setDate+1)%7;
//		System.out.println("checkRemain --> " + checkRemain);
//		if(checkRemain != 0) weekCount += 1;
//		
//		if(dayOfDay != 1 && dayOfDay != 6 && dayOfDay != 7) {
//			weekCount += 1;
//		} 
//
//		return weekCount;
//	}
	
//	// 내가 지금 주차에 있는지 확인
//	public int weekCount() {
//		
//		String today	= today();
//		int lastDay 	= getLastMonth(today);
//		int whatDayNum	= whatDay(today);
//		int setDay		= setDate(whatDayNum);
//		int weekCount   = howManyWeek(lastDay, whatDayNum, setDay);
//		
//		return weekCount;
//	}
	
	// 총 일한시간 구하기
	public String totalWorkTime(List<String> totalTime) throws ParseException {
		log.info("totalWorkTime --> {} ",totalTime);
		
		SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
		
		int hour = 0;
		int min = 0;
		int sec = 0;
		
		// 시,분,초 구하기
		for(int i = 0 ; i < totalTime.size(); i++) {
			Date day = sdf.parse(totalTime.get(i));
			hour += day.getHours();
			min += day.getMinutes();
			sec += day.getSeconds();
		}
		
		// 시간 계산
		min += sec/60;
		sec = sec%60;
		
		hour += min/60;
		min = min%60;
		
		
		System.out.println("hour --> " + hour);
		System.out.println("min --> " + min);
		System.out.println("sec --> " + sec);
		String totalResult = String.format("%02d:%02d:%02d", hour,min,sec);
		System.out.println(totalResult);
		
		return totalResult;
	}

	// 일주일간 초과 근무, 근무시간
	public Map<String, String> sumWeekWorking(String userid) throws ParseException {
		Map<String, String> timeMap = new HashMap<>();
		String today = today();
//		String today = "2022-11-25";
		String weekTotal,weekOver = null;
		int listsize = 0;
		int dayNum = whatDay(today);
		
		
		System.out.println("dayNum - > " + dayNum);
		
		while(dayNum != 1) {
			today = addDate(today,0,0,-1);
			dayNum -= 1;
		}
		
		
		List<String> dayList = new ArrayList<>();
		
		while(dayNum < 6) {
			dayList.add(today);
			today = addDate(today,0,0,1);
			dayNum+=1;
		}
		log.info("sumWeekWorking dayList --> {}",dayList);
		
		List<String> totalTime = attCustomRepository.findTotalTime(dayList,userid);
		totalTime.remove(null);
		log.info("sumWeekWorking totalTime --> {}",totalTime.size());
		listsize = totalTime.size();
		weekTotal = totalWorkTime(totalTime);
		log.info("sumWeekWorking weekTotal --> {}",weekTotal);
		
		
		// 일주일 초과 근무시간 계산
		weekOver = overTimeCal(listsize, weekTotal);
		System.out.println("weekOver -->" + weekOver );
		
		if(weekOver.substring(0,1).equals("-")) {
			weekOver = "00:00:00";
		}
		
		timeMap.put("weekTotal", weekTotal);
		timeMap.put("weekOver", weekOver);
		
		
		return timeMap;
	}
	
	// 초과근무시간 계산하기
	public String overTimeCal(int listsize,String totalTime) throws ParseException {
		int initTime = 8 * listsize;
		String companyWorkTime = String.format("%02d:00:00", initTime);
		String monthOver = timeMinus(totalTime,companyWorkTime);
		
		return monthOver;
	}
	
	// 한달 근무시간
	public Map<String, String> monthTotal(String userid) throws ParseException {
		
		Map<String, String> mapList = new HashMap<>();
		
		// 현재 달 
		String today = today();
		int lastDay = getLastMonth(today);
		String startMonth = setDate(today);
		
		//지난 달 값 구하기
		String lastMonthDay = addDate(startMonth, 0, -1, 0);
		System.out.println("lastMonthDay --> " + lastMonthDay); 
		int monthlastDay = getLastMonth(lastMonthDay);
		
		List<String> dayList = new ArrayList<>();
		List<String> lastMonthDayList = new ArrayList<>();
		
		// 현재달 날짜리스트 구하기
		for(int i = 0 ; i < lastDay ; i++) {
			dayList.add(startMonth);
			startMonth = addDate(startMonth, 0, 0, 1);
		}
		
		// 지난달 날짜 리스트구하기
		for(int i = 0 ; i < monthlastDay ; i++) {
			lastMonthDayList.add(lastMonthDay);
			lastMonthDay = addDate(lastMonthDay, 0, 0, 1);
		}
		System.out.println("LastMonthList--> " + lastMonthDayList);
		log.info("monthTotal dayList.size() --> {}",dayList);
		
		List<String> monthList = attCustomRepository.monthList(dayList,userid);
		List<String> lastMonthList = attCustomRepository.monthList(lastMonthDayList,userid);
		monthList.remove(null);
		lastMonthList.remove(null);
		String monthTotalTime = totalWorkTime(monthList);
		String lastMonthTotal = totalWorkTime(lastMonthList);
		
		// 이번달,지난달 초과 근무시간 표시
		String monthOver = overTimeCal(monthList.size(), monthTotalTime);
		String lastMonthOver = overTimeCal(lastMonthList.size(), lastMonthTotal);
		
		
		// 마이너스일경우 초기화
		if(monthOver.substring(0,1).equals("-")) {
			monthOver = "00:00:00";
		}
		if(lastMonthOver.substring(0,1).equals("-")) {
			lastMonthOver = "00:00:00";
		}
		
		System.out.println("monthTotalLTime --> " + monthTotalTime);
		
		mapList.put("monthTotalTime",monthTotalTime);
		mapList.put("lastMonthTotal",lastMonthTotal);
		mapList.put("monthOver",monthOver);
		mapList.put("lastMonthOver",lastMonthOver);
		
		
		return mapList;
	}


	public long vacation(String userid) {
		
		long vacation = attCustomRepository.findVacation(userid);
		
		return vacation;
	}


	public List<Work> attAllList(int deptno) {
		String today = today();
		String todayStr = today.substring(0,7);
//		String todayStr = null;
		List<Work> attAllList = attCustomRepository.attAllList(deptno,todayStr);
		return attAllList;
	}


	public List<String> monthList() throws ParseException {
		List<String> monthList = new ArrayList<>();
		String today = today();
		today = setDate(today);
		int num = 1;
		int lastDay = getLastMonth(today);
		
		while(num <= lastDay) {
			if(whatDay(today) != 6 && whatDay(today) != 7) monthList.add(today);
			today = addDate(today, 0, 0, 1);
			num++;
		}
		
		return monthList;
	}


	public List<Work> attToMonthAllList(int deptno, String month) {
		List<Work> attAllList = attCustomRepository.attAllList(deptno,month);
		return attAllList;
	}


	public List<String> monthChangeList(String month) throws ParseException {
		List<String> monthList = new ArrayList<>();
		month = month + "-01";
		String subMonth  = "";
		
		int num = 1;
		int lastDay = getLastMonth(month);
		
		while(num <= lastDay) {
			if(whatDay(month) != 6 && whatDay(month) != 7){
					subMonth = month.substring(8);
					monthList.add(subMonth);
				}
			month = addDate(month, 0, 0, 1);
			num++;
		}
		
		return monthList;
	}

	public List<String> memberList(int deptno, String month) {
		List<String> memberList = attCustomRepository.MemberList(deptno,month);
		return memberList;
	}


	public List<String> memberFormList(int deptno) {
		String today = today();
		String todayStr = today.substring(0,7);
		List<String> memberList = attCustomRepository.MemberList(deptno,todayStr);
		return memberList;
	}


	public List<String> findBydeptList() {
		List<String> deptList = attCustomRepository.findBydeptList();
		return deptList;
	}


	public void updateWork(String attOntime, String attOfftime, String workDate, String userid) {
		
		attCustomRepository.updateWork(attOntime,attOfftime,workDate,userid);
		
	}




	
	
	

}
